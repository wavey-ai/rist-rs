use crate::mpegts::{expand_null_packets, suppress_null_packets};
use crate::packet::rtcp::{
    decode_compound, decode_nacks_from_compound, encode_echo, encode_empty_receiver_report,
    encode_nack, encode_nack_chunk, encode_receiver_report, encode_sdes_cname,
    encode_sender_report, Echo, EchoKind, NackMode, ReceiverReport, RtcpPacket, SenderReport,
    MAX_NACK_PACKET_REQUESTS, MAX_NACK_RECORDS_PER_PACKET,
};
use crate::packet::rtp::{
    encode_packet, encode_packet_with_extension, RistRtpExtension, RtpHeader, RtpPacket,
    RTP_PAYLOAD_TYPE_MPEGTS,
};
use crate::recovery::{
    NackRepeat, NackSchedule, SavedPacket, SenderHistory, MAX_TRACKED_HOLE_DISTANCE,
};
use crate::rtt::RttEstimator;
use crate::sequence::extend_near;
use crate::stats::{ReceiverStats, SenderStats};
use crate::time::{calculate_rtt_micros, mpegts_rtp_timestamp, ntp_now};
use crate::{
    CongestionControlMode, MissingTracker, RecoveryConfig, RecoveryMode, RecoveryTuning, Result,
    SequenceExtender,
};
use std::time::{Duration, Instant};

/// Receivers: the minimum gap between two NACK sends of one flow. A NACK
/// goes out at the first poll at which a hole is due (the caller's poll
/// cadence, 1 ms in the bench), not on a fixed grid; this only bounds the
/// NACK packet rate, as librist's 1 ms NACK loop does.
pub const DEFAULT_RTCP_FEEDBACK_INTERVAL: Duration = Duration::from_millis(1);
/// An echo response implying a longer round trip is ignored.
const MAX_RTT_SAMPLE_MICROS: u64 = 10_000_000;
pub const DEFAULT_RTCP_REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Echo requests every 100 ms, as librist (`RIST_PING_INTERVAL`), so both
/// ends keep a current RTT.
pub const DEFAULT_RTCP_ECHO_INTERVAL: Duration = Duration::from_millis(100);
/// NACK packets a receiver flow sends at most per feedback poll.
pub const MAX_NACK_PACKETS_PER_POLL: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryRefusal {
    Spacing,
    MaxRetries,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    pub sequence: u32,
    pub retry: bool,
    pub bytes: Vec<u8>,
}

/// What a sender owes the peer for one feedback compound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedbackOutcome {
    /// Retransmissions of the NACKed sequences that passed the sender's
    /// checks (send these after `responses`).
    pub retries: Vec<OutboundPacket>,
    /// RTCP compounds answering echo requests: an empty receiver report,
    /// SDES and the echo response with delay 0, as librist builds them
    /// (`lr/udp.c:853-867`).
    pub responses: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SimpleSenderPeerState {
    retry_slots: Vec<SenderPeerRetrySlot>,
    retry_mask: usize,
    retry_window_started: Instant,
    retry_window_bytes: u64,
    rtt: RttEstimator,
    stats: SenderStats,
}

#[derive(Debug, Clone, Copy)]
struct SenderPeerRetrySlot {
    sequence: u32,
    retry_count: u32,
    last_retry_at: Option<Instant>,
}

impl SimpleSenderPeerState {
    fn new(flow_id: u32, history_packets: usize) -> Self {
        let capacity = if history_packets == 0 {
            0
        } else {
            history_packets.next_power_of_two()
        };
        Self {
            retry_slots: vec![
                SenderPeerRetrySlot {
                    sequence: 0,
                    retry_count: 0,
                    last_retry_at: None,
                };
                capacity
            ],
            retry_mask: capacity.saturating_sub(1),
            retry_window_started: Instant::now(),
            retry_window_bytes: 0,
            rtt: RttEstimator::new(),
            stats: SenderStats::new(flow_id),
        }
    }

    pub fn stats(&self) -> SenderStats {
        self.stats
    }

    /// The peer's RTT as measured by this sender's echo requests.
    pub fn rtt(&self) -> RttEstimator {
        self.rtt
    }

    pub fn record_send(&mut self, bytes: usize) {
        self.stats.record_send(bytes);
    }

    /// Follows a send history that grew: retry slots are indexed like the
    /// history, so spacing and retry limits stay per sequence.
    fn grow_retry_slots(&mut self, capacity: usize) {
        if self.retry_slots.len() >= capacity || self.retry_slots.is_empty() {
            return;
        }
        let mask = capacity - 1;
        let mut slots = vec![
            SenderPeerRetrySlot {
                sequence: 0,
                retry_count: 0,
                last_retry_at: None,
            };
            capacity
        ];
        for slot in self.retry_slots.drain(..) {
            if slot.last_retry_at.is_some() {
                slots[slot.sequence as usize & mask] = slot;
            }
        }
        self.retry_slots = slots;
        self.retry_mask = mask;
    }

    fn reset_bitrate_window(&mut self) {
        self.retry_window_started = Instant::now();
        self.retry_window_bytes = 0;
    }

    fn take_retry(
        &mut self,
        sequence: u32,
        now: Instant,
        minimum_spacing: Duration,
        maximum_retries: u32,
    ) -> std::result::Result<(), RetryRefusal> {
        let Some(slot) = self
            .retry_slots
            .get_mut(sequence as usize & self.retry_mask)
        else {
            return Err(RetryRefusal::MaxRetries);
        };
        if slot.sequence != sequence {
            *slot = SenderPeerRetrySlot {
                sequence,
                retry_count: 0,
                last_retry_at: None,
            };
        }
        if slot.retry_count >= maximum_retries {
            return Err(RetryRefusal::MaxRetries);
        }
        if slot
            .last_retry_at
            .is_some_and(|last| now.saturating_duration_since(last) < minimum_spacing)
        {
            return Err(RetryRefusal::Spacing);
        }
        slot.retry_count += 1;
        slot.last_retry_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedPayload {
    pub sequence: u32,
    pub recovered: bool,
    pub duplicate: bool,
    pub newly_missing: Vec<u32>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcpIntervals {
    pub feedback: Duration,
    pub report: Duration,
    pub echo: Duration,
}

impl Default for RtcpIntervals {
    fn default() -> Self {
        Self {
            feedback: DEFAULT_RTCP_FEEDBACK_INTERVAL,
            report: DEFAULT_RTCP_REPORT_INTERVAL,
            echo: DEFAULT_RTCP_ECHO_INTERVAL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RtcpScheduler {
    intervals: RtcpIntervals,
    next_report: Option<Instant>,
    next_echo: Option<Instant>,
}

impl RtcpScheduler {
    fn new(intervals: RtcpIntervals) -> Self {
        Self {
            intervals,
            next_report: None,
            next_echo: None,
        }
    }

    fn poll_sender(&mut self, now: Instant) -> RtcpDue {
        RtcpDue {
            report: poll_due(&mut self.next_report, now, self.intervals.report),
            echo: poll_due(&mut self.next_echo, now, self.intervals.echo),
        }
    }

    fn poll_receiver_report(&mut self, now: Instant) -> bool {
        poll_due(&mut self.next_report, now, self.intervals.report)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RtcpDue {
    report: bool,
    echo: bool,
}

fn poll_due(next: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
    let Some(due) = *next else {
        *next = Some(now + interval);
        return false;
    };
    if now < due {
        return false;
    }
    if interval.is_zero() {
        *next = Some(now);
        return true;
    }
    let mut next_due = due + interval;
    while next_due <= now {
        next_due += interval;
    }
    *next = Some(next_due);
    true
}

#[derive(Debug, Clone)]
pub struct SimpleSenderCore {
    ssrc: u32,
    cname: String,
    next_sequence: u32,
    history: SenderHistory,
    null_packet_suppression: bool,
    rtcp: RtcpScheduler,
    stats: SenderStats,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
    tuning: RecoveryTuning,
    recovery_state: SimpleSenderPeerState,
}

impl SimpleSenderCore {
    pub fn new(ssrc: u32, history_packets: usize) -> Self {
        Self {
            ssrc,
            cname: "rust".to_string(),
            next_sequence: 0,
            history: SenderHistory::new(history_packets),
            null_packet_suppression: false,
            rtcp: RtcpScheduler::new(RtcpIntervals::default()),
            stats: SenderStats::new(ssrc),
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
            tuning: RecoveryTuning::default(),
            recovery_state: SimpleSenderPeerState::new(ssrc, history_packets),
        }
        .with_history_retention()
    }

    pub fn with_cname(mut self, cname: impl Into<String>) -> Self {
        self.cname = cname.into();
        self
    }

    pub fn with_rtcp_intervals(mut self, intervals: RtcpIntervals) -> Self {
        self.rtcp = RtcpScheduler::new(intervals);
        self
    }

    pub fn with_null_packet_suppression(mut self, enabled: bool) -> Self {
        self.null_packet_suppression = enabled;
        self
    }

    pub fn with_recovery_config(
        mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) -> Self {
        self.set_recovery_config(recovery, congestion_control);
        self
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.recovery = recovery;
        self.congestion_control = congestion_control;
        self.recovery_state.reset_bitrate_window();
        self.apply_history_retention();
    }

    pub fn with_recovery_tuning(mut self, tuning: RecoveryTuning) -> Self {
        self.set_recovery_tuning(tuning);
        self
    }

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.tuning = tuning;
        self.apply_history_retention();
    }

    pub fn recovery_tuning(&self) -> RecoveryTuning {
        self.tuning
    }

    /// Packets currently addressable in the send history (it grows with
    /// [`RecoveryTuning::history_by_time`]).
    pub fn history_capacity(&self) -> usize {
        self.history.capacity()
    }

    fn with_history_retention(mut self) -> Self {
        self.apply_history_retention();
        self
    }

    /// With `history_by_time`, a packet stays in the history for at least
    /// L + 2 x rtt_max: longer than any repair the age check below can
    /// still allow, so a request is never refused for want of the packet
    /// while the receiver could still use it.
    fn apply_history_retention(&mut self) {
        let retention = if self.tuning.history_by_time {
            effective_recovery_age(&self.recovery)
                + self
                    .recovery
                    .rtt_max
                    .max(self.recovery.rtt_min)
                    .saturating_mul(2)
        } else {
            Duration::ZERO
        };
        self.history
            .set_retention(retention, self.tuning.max_history_packets);
    }

    pub fn enable_null_packet_suppression(&mut self) {
        self.null_packet_suppression = true;
    }

    pub fn disable_null_packet_suppression(&mut self) {
        self.null_packet_suppression = false;
    }

    pub fn null_packet_suppression_enabled(&self) -> bool {
        self.null_packet_suppression
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> OutboundPacket {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.send_payload_with_sequence(sequence, payload, ntp_timestamp, now)
    }

    pub fn send_payload_with_sequence(
        &mut self,
        sequence: u32,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> OutboundPacket {
        let header = RtpHeader::new_mpegts(
            sequence as u16,
            mpegts_rtp_timestamp(ntp_timestamp),
            self.ssrc,
        );
        let bytes = self.encode_payload(header, payload);
        self.history.insert(sequence, bytes.clone(), now);
        self.stats.record_send(bytes.len());
        OutboundPacket {
            sequence,
            retry: false,
            bytes,
        }
    }

    pub fn retransmit(&mut self, sequences: &[u32]) -> Vec<OutboundPacket> {
        self.retransmit_at(sequences, Instant::now())
    }

    pub fn retransmit_at(&mut self, sequences: &[u32], now: Instant) -> Vec<OutboundPacket> {
        let (context, state) = self.split();
        context.retransmit(sequences, now, state)
    }

    pub fn new_peer_state(&self) -> SimpleSenderPeerState {
        SimpleSenderPeerState::new(self.ssrc, self.history.capacity())
    }

    pub fn retransmit_for_peer_at(
        &self,
        state: &mut SimpleSenderPeerState,
        sequences: &[u32],
        now: Instant,
    ) -> Vec<OutboundPacket> {
        self.context().retransmit(sequences, now, state)
    }

    /// Retransmissions for one feedback compound. Echo requests in it are
    /// not answered here; use [`Self::handle_feedback_outcome_at`].
    pub fn handle_feedback(&mut self, packet: &[u8]) -> Result<Vec<OutboundPacket>> {
        self.handle_feedback_at(packet, ntp_now())
    }

    pub fn handle_feedback_at(
        &mut self,
        packet: &[u8],
        now_ntp: u64,
    ) -> Result<Vec<OutboundPacket>> {
        Ok(self
            .handle_feedback_outcome_at(packet, now_ntp, Instant::now())?
            .retries)
    }

    /// Handles one feedback compound: takes RTT samples from echo
    /// responses, answers echo requests and retransmits the NACKed
    /// sequences that pass the sender's checks.
    pub fn handle_feedback_outcome_at(
        &mut self,
        packet: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<FeedbackOutcome> {
        let (context, state) = self.split();
        context.handle_feedback(state, packet, now_ntp, now)
    }

    pub fn handle_feedback_for_peer(
        &self,
        state: &mut SimpleSenderPeerState,
        packet: &[u8],
    ) -> Result<Vec<OutboundPacket>> {
        self.handle_feedback_for_peer_at(state, packet, ntp_now(), Instant::now())
    }

    pub fn handle_feedback_for_peer_at(
        &self,
        state: &mut SimpleSenderPeerState,
        packet: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<Vec<OutboundPacket>> {
        Ok(self
            .handle_feedback_outcome_for_peer_at(state, packet, now_ntp, now)?
            .retries)
    }

    /// [`Self::handle_feedback_outcome_at`] for one peer of a multi-peer
    /// sender.
    pub fn handle_feedback_outcome_for_peer_at(
        &self,
        state: &mut SimpleSenderPeerState,
        packet: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<FeedbackOutcome> {
        self.context().handle_feedback(state, packet, now_ntp, now)
    }

    /// The answer to an echo request: an empty receiver report, SDES and an
    /// echo response with the request's SSRC and timestamp and delay 0.
    pub fn build_echo_response(&self, request: Echo) -> Vec<u8> {
        build_echo_response(self.ssrc, &self.cname, request)
    }

    fn context(&self) -> SenderContext<'_> {
        SenderContext {
            ssrc: self.ssrc,
            cname: &self.cname,
            reference: self.next_sequence.wrapping_sub(1),
            history: &self.history,
            recovery: &self.recovery,
            congestion_control: self.congestion_control,
        }
    }

    /// The shared sender parts beside the single-peer recovery state.
    fn split(&mut self) -> (SenderContext<'_>, &mut SimpleSenderPeerState) {
        (
            SenderContext {
                ssrc: self.ssrc,
                cname: &self.cname,
                reference: self.next_sequence.wrapping_sub(1),
                history: &self.history,
                recovery: &self.recovery,
                congestion_control: self.congestion_control,
            },
            &mut self.recovery_state,
        )
    }

    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    pub fn set_next_sequence(&mut self, sequence: u32) {
        self.next_sequence = sequence;
    }

    pub fn stats(&self) -> SenderStats {
        let recovery = self.recovery_state.stats;
        SenderStats {
            flow_id: self.stats.flow_id,
            sent_packets: self.stats.sent_packets,
            sent_bytes: self.stats.sent_bytes,
            ..recovery
        }
    }

    pub fn build_echo_request(&self, ntp_timestamp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_empty_receiver_report(self.ssrc, &mut out);
        encode_echo(
            Echo {
                ssrc: self.ssrc,
                ntp_timestamp,
                kind: EchoKind::Request,
            },
            &mut out,
        );
        out
    }

    pub fn build_sender_report(&self, ntp_timestamp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_sender_report(ntp_timestamp, &mut out);
        out
    }

    pub fn poll_rtcp(&mut self, now: Instant, ntp_timestamp: u64) -> Option<Vec<u8>> {
        let due = self.rtcp.poll_sender(now);
        if !due.report && !due.echo {
            return None;
        }

        let mut out = Vec::new();
        if due.report {
            self.encode_sender_report(ntp_timestamp, &mut out);
        } else {
            encode_empty_receiver_report(self.ssrc, &mut out);
        }
        if due.echo {
            encode_echo(
                Echo {
                    ssrc: self.ssrc,
                    ntp_timestamp,
                    kind: EchoKind::Request,
                },
                &mut out,
            );
        }
        Some(out)
    }

    fn encode_sender_report(&self, ntp_timestamp: u64, out: &mut Vec<u8>) {
        encode_sender_report(
            SenderReport {
                ssrc: self.ssrc,
                ntp_timestamp,
                rtp_timestamp: mpegts_rtp_timestamp(ntp_timestamp),
                sender_packets: self.stats.sent_packets.min(u64::from(u32::MAX)) as u32,
                sender_bytes: self.stats.sent_bytes.min(u64::from(u32::MAX)) as u32,
            },
            out,
        );
        encode_sdes_cname(self.ssrc, &self.cname, out);
    }

    fn encode_payload(&self, header: RtpHeader, payload: &[u8]) -> Vec<u8> {
        if !self.null_packet_suppression
            || payload.len() > 7 * crate::mpegts::TS_PACKET_SIZE_WITH_RS
        {
            return encode_packet(header, payload);
        }

        match suppress_null_packets(payload) {
            Ok(suppressed) if suppressed.bytes_suppressed > 0 => encode_packet_with_extension(
                header,
                RistRtpExtension::new_npd(suppressed.npd_bits),
                &suppressed.payload,
            ),
            _ => encode_packet(header, payload),
        }
    }
}

fn retransmit_from_history(
    context: &SenderContext<'_>,
    sequences: &[u32],
    now: Instant,
    state: &mut SimpleSenderPeerState,
) -> Vec<OutboundPacket> {
    let history = context.history;
    let recovery = context.recovery;
    let congestion_control = context.congestion_control;
    state.stats.nack_requests += sequences.len() as u64;
    if recovery.mode == RecoveryMode::Disabled {
        return Vec::new();
    }
    if now.saturating_duration_since(state.retry_window_started) >= Duration::from_secs(1) {
        state.retry_window_started = now;
        state.retry_window_bytes = 0;
    }
    let spacing = sender_retry_spacing(&state.rtt, recovery, congestion_control);
    let maximum_bytes = u64::from(recovery.max_bitrate)
        .saturating_mul(1_000)
        .saturating_div(8);
    let mut packets = Vec::new();
    let rtt = state
        .rtt
        .for_renack()
        .unwrap_or(recovery.rtt_min)
        .clamp(recovery.rtt_min, recovery.rtt_max.max(recovery.rtt_min));
    for &sequence in sequences {
        let Some(packet) = history.get(sequence) else {
            state.stats.retransmit_refused_not_in_history += 1;
            continue;
        };
        if !context.repair_still_useful(packet, now, rtt) {
            state.stats.retransmit_refused_too_old += 1;
            continue;
        }
        if maximum_bytes > 0
            && state
                .retry_window_bytes
                .saturating_add(packet.payload_len as u64)
                > maximum_bytes
        {
            state.stats.retransmit_refused_bitrate += 1;
            continue;
        }
        match state.take_retry(sequence, now, spacing, recovery.max_retries) {
            Ok(()) => {}
            Err(RetryRefusal::Spacing) => {
                state.stats.retransmit_refused_spacing += 1;
                continue;
            }
            Err(RetryRefusal::MaxRetries) => {
                state.stats.retransmit_refused_max_retries += 1;
                continue;
            }
        }
        state.retry_window_bytes = state
            .retry_window_bytes
            .saturating_add(packet.payload_len as u64);
        state.stats.record_retransmit(packet.payload_len);
        packets.push(OutboundPacket {
            sequence: packet.sequence,
            retry: true,
            bytes: retry_marked(&packet.payload),
        });
    }
    packets
}

/// Byte 11 of an RTP packet holds the SSRC's least significant bit.
const RTP_SSRC_LSB_OFFSET: usize = 11;

/// A copy of a stored RTP packet with the SSRC retry bit set, as librist
/// marks retransmissions (`flow_id | 1`). Receivers clear the bit and use it
/// to tell repairs from originals.
fn retry_marked(rtp: &[u8]) -> Vec<u8> {
    let mut bytes = rtp.to_vec();
    if let Some(byte) = bytes.get_mut(RTP_SSRC_LSB_OFFSET) {
        *byte |= 1;
    }
    bytes
}

/// The parts of a [`SimpleSenderCore`] that serve one peer's feedback, so the
/// single-peer state can be borrowed beside them.
struct SenderContext<'a> {
    ssrc: u32,
    cname: &'a str,
    reference: u32,
    history: &'a SenderHistory,
    recovery: &'a RecoveryConfig,
    congestion_control: CongestionControlMode,
}

impl SenderContext<'_> {
    fn handle_feedback(
        &self,
        state: &mut SimpleSenderPeerState,
        packet: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<FeedbackOutcome> {
        state.stats.record_feedback();
        let mut echo_requests = Vec::new();
        let sequences =
            decode_sender_feedback(packet, now_ntp, self.reference, state, &mut echo_requests)?;
        let responses = echo_requests
            .into_iter()
            .map(|request| build_echo_response(self.ssrc, self.cname, request))
            .collect::<Vec<_>>();
        state.stats.echo_responses += responses.len() as u64;
        let retries = self.retransmit(&sequences, now, state);
        Ok(FeedbackOutcome { retries, responses })
    }

    fn retransmit(
        &self,
        sequences: &[u32],
        now: Instant,
        state: &mut SimpleSenderPeerState,
    ) -> Vec<OutboundPacket> {
        state.grow_retry_slots(self.history.capacity());
        retransmit_from_history(self, sequences, now, state)
    }

    /// Whether a repair of `packet` sent now can still be used.
    ///
    /// The receiver detects a hole when a later packet arrives and keeps
    /// asking for L after that (rist-rs; librist about 1.1 x L after an
    /// interpolated insertion time). So the useful age runs from the send
    /// time of the successor, not of the packet: for the last packet of a
    /// frame the successor is the next frame, a frame interval later. A
    /// request is refused only when both
    /// - the packet is older than L + 2 x rtt_min (librist's sender bound),
    ///   and
    /// - its successor was sent more than L + rtt + 5 ms ago (rtt =
    ///   clamp(measured, rtt_min, rtt_max)).
    ///
    /// The newest packet (no successor sent) is always served: no receiver
    /// can have found it missing by sequence.
    fn repair_still_useful(&self, packet: &SavedPacket, now: Instant, rtt: Duration) -> bool {
        let length = effective_recovery_age(self.recovery);
        let age = now.saturating_duration_since(packet.inserted_at);
        if age <= length + self.recovery.rtt_min.saturating_mul(2) {
            return true;
        }
        if packet.sequence == self.reference {
            return true;
        }
        let since_successor =
            now.saturating_duration_since(successor_sent_at(self.history, packet));
        since_successor <= length + rtt + REPAIR_AGE_SLACK
    }
}

/// Slack on the sender's repair age for jitter between the paths.
const REPAIR_AGE_SLACK: Duration = Duration::from_millis(5);

/// When the packet after `packet` was first sent (`packet`'s own send time
/// when the successor is not in the history).
fn successor_sent_at(history: &SenderHistory, packet: &SavedPacket) -> Instant {
    history
        .get(packet.sequence.wrapping_add(1))
        .map(|successor| successor.inserted_at)
        .filter(|sent| *sent >= packet.inserted_at)
        .unwrap_or(packet.inserted_at)
}

fn build_echo_response(ssrc: u32, cname: &str, request: Echo) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    encode_empty_receiver_report(ssrc, &mut out);
    encode_sdes_cname(ssrc, cname, &mut out);
    encode_echo(
        Echo {
            ssrc: request.ssrc,
            ntp_timestamp: request.ntp_timestamp,
            kind: EchoKind::Response { delay: 0 },
        },
        &mut out,
    );
    out
}

/// The minimum time between two repairs of one sequence for one peer:
/// 0.9 x clamp(rtt, rtt_min, rtt_max), doubled in aggressive mode, none
/// with congestion control off. `rtt` is the smaller of the smoothed and the
/// last echo sample, so the sender errs early: a receiver re-requests after
/// 1.1 x its own (larger) estimate, and a copy of a NACK sent a few
/// milliseconds after the first is still refused.
fn sender_retry_spacing(
    rtt: &RttEstimator,
    recovery: &RecoveryConfig,
    congestion_control: CongestionControlMode,
) -> Duration {
    let rtt = rtt
        .for_spacing()
        .unwrap_or(recovery.rtt_min)
        .clamp(recovery.rtt_min, recovery.rtt_max.max(recovery.rtt_min));
    match congestion_control {
        CongestionControlMode::Off => Duration::ZERO,
        CongestionControlMode::Normal => rtt.mul_f64(0.9),
        CongestionControlMode::Aggressive => rtt.mul_f64(1.8),
    }
}

/// Decodes one feedback compound for a sender: takes RTT samples from echo
/// responses, collects echo requests and returns the NACKed sequences
/// extended near `reference`. Decode failures are counted.
fn decode_sender_feedback(
    packet: &[u8],
    now_ntp: u64,
    reference: u32,
    state: &mut SimpleSenderPeerState,
    echo_requests: &mut Vec<Echo>,
) -> Result<Vec<u32>> {
    let decoded = update_sender_rtcp_state(packet, now_ntp, state, echo_requests)
        .and_then(|()| decode_nacks_from_compound(packet));
    match decoded {
        Ok(sequences) => Ok(sequences
            .into_iter()
            .map(|sequence| extend_near(reference, sequence as u16))
            .collect()),
        Err(error) => {
            state.stats.feedback_decode_errors += 1;
            Err(error)
        }
    }
}

fn update_sender_rtcp_state(
    packet: &[u8],
    now_ntp: u64,
    state: &mut SimpleSenderPeerState,
    echo_requests: &mut Vec<Echo>,
) -> Result<()> {
    for packet in decode_compound(packet)? {
        match packet {
            RtcpPacket::Echo(Echo {
                ntp_timestamp,
                kind: EchoKind::Response { delay },
                ..
            }) => {
                state
                    .rtt
                    .sample(calculate_rtt_micros(ntp_timestamp, now_ntp, delay));
                state.stats.rtt_micros = state.rtt.srtt_micros();
            }
            RtcpPacket::Echo(
                request @ Echo {
                    kind: EchoKind::Request,
                    ..
                },
            ) => echo_requests.push(request),
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SimpleReceiverCore {
    flow_id: u32,
    cname: String,
    nack_mode: NackMode,
    sequence_extender: SequenceExtender,
    missing_tracker: MissingTracker,
    peer_ssrc: Option<u32>,
    base_sequence: Option<u32>,
    highest_sequence: Option<u32>,
    last_sender_report: Option<(u64, u64)>,
    rtcp: RtcpScheduler,
    stats: ReceiverStats,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
    return_window_started: Instant,
    return_window_bytes: u64,
    nack_scratch: Vec<u32>,
    nack_packet_scratch: Vec<u8>,
    tuning: RecoveryTuning,
    rtt: RttEstimator,
    /// Next echo request; set at the first data packet.
    next_echo_at: Option<Instant>,
    /// No NACK packet before this instant (the feedback interval).
    next_nack_packet_at: Option<Instant>,
    /// Largest recent reordering, for the adaptive first-NACK delay.
    reorder: ReorderEstimate,
    /// A retry-marked packet was seen: unmarked arrivals are originals.
    sender_marks_retries: bool,
}

/// The largest recent displacement of an original packet (hole detection
/// to arrival), decaying with a fixed half-life.
#[derive(Debug, Clone, Copy, Default)]
struct ReorderEstimate {
    micros: f64,
    at: Option<Instant>,
}

const REORDER_HALF_LIFE_SECS: f64 = 10.0;

impl ReorderEstimate {
    fn at(&self, now: Instant) -> Duration {
        let Some(at) = self.at else {
            return Duration::ZERO;
        };
        let elapsed = now.saturating_duration_since(at).as_secs_f64();
        let decayed = self.micros * (-elapsed / REORDER_HALF_LIFE_SECS).exp2();
        Duration::from_micros(decayed as u64)
    }

    fn sample(&mut self, displacement: Duration, now: Instant) {
        let current = self.at(now).as_micros() as f64;
        self.micros = current.max(displacement.as_micros() as f64);
        self.at = Some(now);
    }
}

impl SimpleReceiverCore {
    pub fn new(flow_id: u32, cname: impl Into<String>, nack_mode: NackMode) -> Self {
        Self {
            flow_id,
            cname: cname.into(),
            nack_mode,
            sequence_extender: SequenceExtender::new(),
            missing_tracker: default_receiver_tracker(),
            peer_ssrc: None,
            base_sequence: None,
            highest_sequence: None,
            last_sender_report: None,
            rtcp: RtcpScheduler::new(RtcpIntervals::default()),
            stats: ReceiverStats::new(flow_id),
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
            return_window_started: Instant::now(),
            return_window_bytes: 0,
            nack_scratch: Vec::new(),
            nack_packet_scratch: Vec::new(),
            tuning: RecoveryTuning::default(),
            rtt: RttEstimator::new(),
            next_echo_at: None,
            next_nack_packet_at: None,
            reorder: ReorderEstimate::default(),
            sender_marks_retries: false,
        }
    }

    pub fn with_rtcp_intervals(mut self, intervals: RtcpIntervals) -> Self {
        self.rtcp = RtcpScheduler::new(intervals);
        self
    }

    pub fn with_recovery_tuning(mut self, tuning: RecoveryTuning) -> Self {
        self.set_recovery_tuning(tuning);
        self
    }

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.tuning = tuning;
    }

    pub fn recovery_tuning(&self) -> RecoveryTuning {
        self.tuning
    }

    /// The RTT this receiver measured (echo and Karn samples).
    pub fn rtt(&self) -> RttEstimator {
        self.rtt
    }

    pub fn with_recovery_config(
        mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) -> Self {
        self.set_recovery_config(recovery, congestion_control);
        self
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.missing_tracker.reconfigure(
            recovery_window_packets(&recovery),
            effective_recovery_age(&recovery),
        );
        self.missing_tracker
            .set_initial_nack_delay(recovery.reorder_buffer);
        self.recovery = recovery;
        self.congestion_control = congestion_control;
        self.return_window_started = Instant::now();
        self.return_window_bytes = 0;
    }

    pub fn accept_packet(&mut self, packet: &[u8]) -> Result<ReceivedPayload> {
        self.accept_packet_at(packet, Instant::now())
    }

    /// [`Self::accept_packet`] with the caller's clock reading.
    pub fn accept_packet_at(&mut self, packet: &[u8], now: Instant) -> Result<ReceivedPayload> {
        let packet = RtpPacket::decode(packet)?;
        self.accept_rtp_packet_at(packet, now)
    }

    pub fn accept_rtp_packet(&mut self, packet: RtpPacket<'_>) -> Result<ReceivedPayload> {
        self.accept_rtp_packet_at(packet, Instant::now())
    }

    /// [`Self::accept_rtp_packet`] with the caller's clock reading, so a
    /// transport that already read the clock for the datagram does not read
    /// it again.
    ///
    /// A set SSRC least significant bit marks a retransmission (librist, and
    /// rist-rs senders since P7): it is cleared before the SSRC is compared,
    /// so a repair never looks like a new sender.
    pub fn accept_rtp_packet_at(
        &mut self,
        mut packet: RtpPacket<'_>,
        now: Instant,
    ) -> Result<ReceivedPayload> {
        let retry = packet.header.ssrc & 1 == 1;
        packet.header.ssrc &= !1;
        self.accept_rtp_packet_with_retry_at(packet, retry, now)
    }

    /// [`Self::accept_rtp_packet_at`] for a transport that already read and
    /// cleared the retry bit of the SSRC (the Main profile keys flows by
    /// `ssrc & !1`). `retry` says whether the datagram was a retransmission.
    pub fn accept_rtp_packet_with_retry_at(
        &mut self,
        packet: RtpPacket<'_>,
        retry: bool,
        now: Instant,
    ) -> Result<ReceivedPayload> {
        if packet.header.payload_type != RTP_PAYLOAD_TYPE_MPEGTS {
            return Err(crate::Error::UnsupportedRtpPayloadType(
                packet.header.payload_type,
            ));
        }
        if self
            .peer_ssrc
            .is_some_and(|peer_ssrc| peer_ssrc != packet.header.ssrc)
        {
            self.sequence_extender.reset();
            self.missing_tracker.reset();
            self.base_sequence = None;
            self.highest_sequence = None;
        }
        let sequence = match self.highest_sequence {
            Some(highest) => self.extend_received(highest, packet.header.sequence_number),
            None => self.sequence_extender.extend(packet.header.sequence_number),
        };
        self.peer_ssrc = Some(packet.header.ssrc);
        if self.base_sequence.is_none() {
            self.base_sequence = Some(sequence);
        }
        self.highest_sequence = Some(match self.highest_sequence {
            Some(highest) if (sequence.wrapping_sub(highest) as i32) <= 0 => highest,
            _ => sequence,
        });
        let observation = self.missing_tracker.observe_at(sequence, now);
        if retry {
            self.stats.retry_packets_received += 1;
        }
        if observation.recovered {
            self.on_hole_recovered(retry, now);
        }
        if !observation.newly_missing.is_empty() {
            // Keep next_poll_at() exact for the new holes.
            let delay = self.first_nack_delay(now);
            self.missing_tracker.set_initial_nack_delay(delay);
        }
        if self.tuning.measure_rtt && self.next_echo_at.is_none() {
            // The first echo request goes out with the first report.
            self.next_echo_at = Some(now);
        }
        let payload = if let Some(extension) = packet.extension {
            if extension.has_null_packet_deletion() {
                // NPD is an optional transform. A malformed/sender-specific
                // deletion map must not turn a valid RTP payload into loss.
                expand_null_packets(packet.payload, extension.npd_bits)
                    .unwrap_or_else(|_| packet.payload.to_vec())
            } else {
                packet.payload.to_vec()
            }
        } else {
            packet.payload.to_vec()
        };
        let currently_missing = self.missing_tracker.missing_len();
        self.stats.record_receive(
            payload.len(),
            observation.duplicate,
            observation.recovered,
            observation.newly_missing.len(),
            currently_missing,
        );
        Ok(ReceivedPayload {
            sequence,
            recovered: observation.recovered,
            duplicate: observation.duplicate,
            newly_missing: observation.newly_missing,
            payload,
        })
    }

    /// Takes a Karn sample from the hole just recovered: only a repair
    /// marked as a retransmission, of a hole NACKed exactly once, gives an
    /// unambiguous NACK-to-repair time. It includes the sender's service
    /// delay, which is what the re-NACK interval has to cover.
    ///
    /// An original that fills a hole is a reordering sample for the
    /// adaptive first-NACK delay: always when the sender marks its
    /// retransmissions (seen once), otherwise only when no NACK went out
    /// yet or the arrival came too soon after it to be its repair.
    fn on_hole_recovered(&mut self, retry: bool, now: Instant) {
        let Some(hole) = self.missing_tracker.last_recovered() else {
            return;
        };
        if retry {
            self.sender_marks_retries = true;
        } else {
            let half_rtt = self
                .rtt
                .min_micros()
                .map_or(self.recovery.rtt_min, Duration::from_micros)
                / 2;
            let original = self.sender_marks_retries
                || hole.nack_count == 0
                || hole
                    .last_nack_at
                    .is_some_and(|nacked| now.saturating_duration_since(nacked) < half_rtt);
            if original {
                self.reorder
                    .sample(now.saturating_duration_since(hole.first_missing_at), now);
                self.stats.reorder_samples += 1;
            }
        }
        if retry && self.tuning.measure_rtt && hole.nack_count == 1 {
            if let Some(nacked_at) = hole.last_nack_at {
                let sample = now.saturating_duration_since(nacked_at);
                if !sample.is_zero() {
                    self.rtt.sample_duration(sample);
                    self.stats.rtt_samples_karn += 1;
                }
            }
        }
    }

    /// Extends a received 16-bit sequence relative to the highest sequence
    /// seen, not the last packet, so a repair far behind does not shift the
    /// cycle of the next packet.
    ///
    /// A low-16 value up to 32767 behind the highest is read as behind only
    /// when that reading can be a repair or a duplicate: it is within the
    /// duplicate-detection ring, or an open (or recovered) hole is tracked
    /// for it. Otherwise it is read forward, as the first packet after a gap
    /// of more than 32767 (a long outage), so the tracker moves its highest
    /// sequence on instead of refusing every later packet as a duplicate.
    fn extend_received(&self, highest: u32, sequence: u16) -> u32 {
        let near = extend_near(highest, sequence);
        let behind = highest.wrapping_sub(near);
        if behind == 0 || behind >= 1 << 31 {
            return near;
        }
        if (behind as usize) < self.missing_tracker.capacity()
            || (behind <= MAX_TRACKED_HOLE_DISTANCE && self.missing_tracker.hole(near).is_some())
        {
            return near;
        }
        highest.wrapping_add(u32::from(sequence.wrapping_sub(highest as u16)))
    }

    pub fn build_feedback(&self) -> Vec<u8> {
        self.build_feedback_at(ntp_now())
    }

    pub fn build_feedback_at(&self, now_ntp: u64) -> Vec<u8> {
        let missing = self.missing_tracker.missing_sequences().collect::<Vec<_>>();
        let mut out = self.build_receiver_report(now_ntp);
        encode_nack(self.nack_mode, self.flow_id, &missing, &mut out);
        out
    }

    pub fn build_feedback_and_record(&mut self) -> Vec<u8> {
        self.build_feedback_and_record_at(ntp_now())
    }

    pub fn build_feedback_and_record_at(&mut self, now_ntp: u64) -> Vec<u8> {
        self.stats.record_feedback();
        self.build_feedback_at(now_ntp)
    }

    pub fn build_receiver_report(&self, now_ntp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_receiver_report(now_ntp, &mut out);
        out
    }

    /// Returns the next due RTCP packet: a NACK (with a full receiver report)
    /// or a periodic receiver report. Returns at most one packet; holes that
    /// do not fit stay due for the next poll. See [`Self::poll_rtcp_into`].
    pub fn poll_rtcp(&mut self, now: Instant, now_ntp: u64) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.poll_rtcp_into(now, now_ntp, &mut out, 1);
        out.pop()
    }

    /// Appends up to `max_packets` due RTCP packets to `out` and returns how
    /// many it appended.
    ///
    /// Due holes are requested oldest first, in packets of at most
    /// [`MAX_NACK_RECORDS_PER_PACKET`] records (and at most 4096 sequences),
    /// each a full receiver report + SDES + NACK compound. A hole counts as
    /// requested only when its packet is returned: holes beyond
    /// `max_packets` stay due, and holes refused by the return bandwidth
    /// (`return_max_bitrate`, or `max_bitrate`) are deferred to the next
    /// budget window. A hole is requested at most once per poll, whatever
    /// the repeat delay. When no NACK goes out, a due periodic receiver
    /// report is returned instead.
    pub fn poll_rtcp_into(
        &mut self,
        now: Instant,
        now_ntp: u64,
        out: &mut Vec<Vec<u8>>,
        max_packets: usize,
    ) -> usize {
        self.poll_rtcp_with(now, now_ntp, max_packets, |packet| {
            out.push(packet.to_vec());
            true
        })
    }

    /// [`Self::poll_rtcp_into`] for a transport that sends each packet as it
    /// is built: `send` puts one packet on the wire and returns whether it
    /// went out. Holes count as requested (NACK count, repeat schedule,
    /// [`ReceiverStats`] NACK counters) only once `send` accepted their
    /// packet. When `send` returns `false`, the holes of that packet and of
    /// every packet not yet built stay due from `now`, nothing more is sent
    /// in this poll, and the return bandwidth charged for the refused packet
    /// is given back. Returns the number of packets `send` accepted.
    pub fn poll_rtcp_with<F>(
        &mut self,
        now: Instant,
        now_ntp: u64,
        max_packets: usize,
        mut send: F,
    ) -> usize
    where
        F: FnMut(&[u8]) -> bool,
    {
        if max_packets == 0 {
            return 0;
        }
        // Nothing is offered to `send` after it refused a packet.
        let mut refused = false;
        let mut send = |packet: &[u8]| {
            refused = refused || !send(packet);
            !refused
        };
        let report_due = self.rtcp.poll_receiver_report(now);
        let mut echo = self.echo_due(now);
        let mut produced = 0;
        let first_nack_delay = self.first_nack_delay(now);
        self.missing_tracker
            .set_initial_nack_delay(first_nack_delay);
        self.stats.first_nack_delay_micros = first_nack_delay.as_micros() as u64;
        if self.nack_packet_due(now) {
            let (count, echo_sent) =
                self.push_due_nacks(now, now_ntp, max_packets, echo, &mut send);
            produced = count;
            if produced > 0 {
                self.next_nack_packet_at = Some(now + self.rtcp.intervals.feedback);
            }
            if echo_sent {
                self.echo_sent(now);
                echo = false;
            }
        }
        if produced == 0 && (report_due || echo) {
            let mut report = Vec::with_capacity(96);
            self.encode_receiver_report(now_ntp, &mut report);
            if echo {
                self.encode_echo_request(now_ntp, &mut report);
            }
            if send(&report) {
                self.stats.record_feedback();
                produced = 1;
                if echo {
                    self.echo_sent(now);
                }
            }
        }
        produced
    }

    /// The earliest instant at which [`Self::poll_rtcp_with`] can have
    /// something to send: a due NACK (not before the feedback interval since
    /// the last NACK packet), an echo request or a periodic report. `None`
    /// when nothing is scheduled. It can be early, never late. O(1).
    pub fn next_poll_at(&self) -> Option<Instant> {
        let nack = self
            .missing_tracker
            .next_nack_at()
            .map(|at| self.next_nack_packet_at.map_or(at, |gap| at.max(gap)));
        let echo = self.next_echo_at.filter(|_| self.tuning.measure_rtt);
        [nack, echo, self.rtcp.next_report]
            .into_iter()
            .flatten()
            .min()
    }

    /// The first-NACK delay: `reorder_buffer`, or with
    /// `adaptive_first_nack` clamp(1.5 x observed reordering + 1 ms,
    /// first_nack_floor, reorder_buffer), the reordering decaying with a
    /// 10 s half-life. On a path that does not reorder the first NACK goes
    /// out within a few milliseconds, which buys an attempt and lands a
    /// lost frame tail within the frame deadline at short RTTs.
    pub fn first_nack_delay(&self, now: Instant) -> Duration {
        let ceiling = self.recovery.reorder_buffer;
        if !self.tuning.adaptive_first_nack {
            return ceiling;
        }
        let adaptive = self
            .reorder
            .at(now)
            .mul_f64(1.5)
            .saturating_add(Duration::from_millis(1));
        adaptive.max(self.tuning.first_nack_floor).min(ceiling)
    }

    fn nack_packet_due(&self, now: Instant) -> bool {
        self.next_nack_packet_at.map_or(true, |at| now >= at)
            && self
                .missing_tracker
                .next_nack_at()
                .is_some_and(|at| at <= now)
    }

    fn echo_due(&self, now: Instant) -> bool {
        self.tuning.measure_rtt && self.next_echo_at.is_some_and(|at| now >= at)
    }

    fn echo_sent(&mut self, now: Instant) {
        self.next_echo_at = Some(now + self.rtcp.intervals.echo);
        self.stats.echo_requests_sent += 1;
    }

    fn encode_echo_request(&self, now_ntp: u64, out: &mut Vec<u8>) {
        encode_echo(
            Echo {
                ssrc: self.flow_id,
                ntp_timestamp: now_ntp,
                kind: EchoKind::Request,
            },
            out,
        );
    }

    /// The NACK timing for this poll.
    ///
    /// - First NACK after `reorder_buffer`.
    /// - Re-NACK after 1.1 x rtt_c + `renack_margin` (2.2 x in aggressive
    ///   mode, as the sender doubles its spacing), with
    ///   rtt_c = clamp(max(srtt, last), rtt_min, rtt_max), as librist
    ///   (`lr/rist-common.c:1045-1063`) but with the receiver's own RTT.
    /// - Until the first RTT sample the repeat delay doubles per attempt,
    ///   so a long path is not flooded when rtt_min is small.
    /// - A hole is no longer requested when less than one measured RTT is
    ///   left before its deadline: the repair could not arrive in time.
    fn nack_schedule(&self, now: Instant) -> (NackSchedule, NackRepeat) {
        let recovery = &self.recovery;
        let rtt_min = recovery.rtt_min;
        let rtt_max = recovery.rtt_max.max(rtt_min);
        let measuring = self.tuning.measure_rtt;
        let measured = measuring.then(|| self.rtt.for_renack()).flatten();
        let rtt = measured.unwrap_or(rtt_min).clamp(rtt_min, rtt_max);
        let multiplier = match self.congestion_control {
            CongestionControlMode::Aggressive => 2.2,
            CongestionControlMode::Off | CongestionControlMode::Normal => 1.1,
        };
        // A copy of each NACK a few ms later (B2): the sender refuses it
        // by its spacing when the first arrived. Not with congestion control
        // off (the sender would serve every copy), and not when the gap
        // would come near the sender's spacing (tiny rtt_min).
        let copy_gap = (rtt / 20).clamp(Duration::from_millis(1), Duration::from_millis(5));
        let copy_gap = (self.tuning.redundant_nacks
            && self.congestion_control != CongestionControlMode::Off
            && copy_gap.saturating_mul(2) <= rtt)
            .then_some(copy_gap);
        // The next attempt is 1.1 x rtt after the copy reached the sender.
        let repeat = NackRepeat {
            delay: rtt.mul_f64(multiplier)
                + self.tuning.renack_margin
                + copy_gap.unwrap_or_default(),
            backoff: measuring && measured.is_none(),
            copy_gap,
        };
        let min_time_left = if measuring {
            self.rtt.for_spacing().unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        };
        let schedule = NackSchedule {
            initial_delay: self.first_nack_delay(now),
            repeat_delay: repeat.delay,
            max_retries: recovery.max_retries,
            min_time_left,
        };
        (schedule, repeat)
    }

    /// Takes the due holes once, sized by what `max_packets` packets can
    /// carry, and encodes them into packets oldest first. Holes committed
    /// here are never taken again in the same poll, even with a zero repeat
    /// delay; holes that do not fit stay due from `now`.
    ///
    /// With `echo`, the first packet also carries an echo request; returns
    /// the packets sent and whether that first packet went out.
    fn push_due_nacks(
        &mut self,
        now: Instant,
        now_ntp: u64,
        max_packets: usize,
        echo: bool,
        send: &mut dyn FnMut(&[u8]) -> bool,
    ) -> (usize, bool) {
        let (schedule, repeat) = self.nack_schedule(now);
        let mut due = std::mem::take(&mut self.nack_scratch);
        due.clear();
        // A Range packet can carry up to MAX_NACK_PACKET_REQUESTS contiguous
        // sequences, so take enough for every packet left to be full; at most
        // the whole horizon, which bounds the tracked holes anyway.
        let limit = max_packets
            .saturating_mul(MAX_NACK_PACKET_REQUESTS)
            .min(MAX_TRACKED_HOLE_DISTANCE as usize + 1);
        self.missing_tracker
            .take_due_nacks(now, &schedule, limit, &mut due);
        let mut produced = 0;
        let mut sent = 0;
        let mut echo_sent = false;
        let mut retry_at = now;
        if !due.is_empty() {
            let mut packet = std::mem::take(&mut self.nack_packet_scratch);
            packet.clear();
            self.encode_receiver_report(now_ntp, &mut packet);
            let prefix_len = packet.len();
            while sent < due.len() && produced < max_packets {
                packet.truncate(prefix_len);
                let count = encode_nack_chunk(
                    self.nack_mode,
                    self.flow_id,
                    &due[sent..],
                    MAX_NACK_RECORDS_PER_PACKET,
                    &mut packet,
                );
                let with_echo = echo && produced == 0;
                if with_echo {
                    self.encode_echo_request(now_ntp, &mut packet);
                }
                if !self.allow_return_bytes(now, packet.len()) {
                    retry_at = self.return_window_started + Duration::from_secs(1);
                    break;
                }
                if !send(&packet) {
                    self.return_window_bytes =
                        self.return_window_bytes.saturating_sub(packet.len() as u64);
                    break;
                }
                self.missing_tracker
                    .commit_nacks_with(&due[sent..sent + count], now, repeat);
                self.stats.record_nack_packet(count);
                echo_sent |= with_echo;
                produced += 1;
                sent += count;
            }
            self.nack_packet_scratch = packet;
        }
        let stopped = sent < due.len();
        if stopped {
            self.missing_tracker.defer_nacks(&due[sent..], retry_at);
            self.stats.nack_entries_deferred += (due.len() - sent) as u64;
        }
        due.clear();
        if !stopped && produced < max_packets {
            let copy_limit = (max_packets - produced).saturating_mul(MAX_NACK_PACKET_REQUESTS);
            self.missing_tracker
                .take_due_copies(now, copy_limit, &mut due);
            let (copies, copy_echo) =
                self.send_nack_copies(&due, now, now_ntp, echo && produced == 0, send);
            produced += copies;
            echo_sent |= copy_echo;
            due.clear();
        }
        self.nack_scratch = due;
        (produced, echo_sent)
    }

    /// Sends NACK copies (best effort: copies that do not fit the return
    /// budget or are refused by `send` are dropped; holes are unchanged).
    fn send_nack_copies(
        &mut self,
        copies: &[u32],
        now: Instant,
        now_ntp: u64,
        echo: bool,
        send: &mut dyn FnMut(&[u8]) -> bool,
    ) -> (usize, bool) {
        let mut produced = 0;
        let mut echo_sent = false;
        let mut sent = 0;
        let mut packet = std::mem::take(&mut self.nack_packet_scratch);
        packet.clear();
        if !copies.is_empty() {
            self.encode_receiver_report(now_ntp, &mut packet);
        }
        let prefix_len = packet.len();
        while sent < copies.len() {
            packet.truncate(prefix_len);
            let count = encode_nack_chunk(
                self.nack_mode,
                self.flow_id,
                &copies[sent..],
                MAX_NACK_RECORDS_PER_PACKET,
                &mut packet,
            );
            let with_echo = echo && produced == 0;
            if with_echo {
                self.encode_echo_request(now_ntp, &mut packet);
            }
            if !self.allow_return_bytes(now, packet.len()) {
                break;
            }
            if !send(&packet) {
                self.return_window_bytes =
                    self.return_window_bytes.saturating_sub(packet.len() as u64);
                break;
            }
            self.stats.feedback_packets += 1;
            self.stats.nack_packets += 1;
            self.stats.nack_copies_sent += count as u64;
            echo_sent |= with_echo;
            produced += 1;
            sent += count;
        }
        self.nack_packet_scratch = packet;
        (produced, echo_sent)
    }

    fn allow_return_bytes(&mut self, now: Instant, bytes: usize) -> bool {
        if now.saturating_duration_since(self.return_window_started) >= Duration::from_secs(1) {
            self.return_window_started = now;
            self.return_window_bytes = 0;
        }
        let bitrate = if self.recovery.return_max_bitrate == 0 {
            self.recovery.max_bitrate
        } else {
            self.recovery.return_max_bitrate
        };
        let maximum_bytes = u64::from(bitrate).saturating_mul(1_000).saturating_div(8);
        if self.return_window_bytes.saturating_add(bytes as u64) > maximum_bytes {
            return false;
        }
        self.return_window_bytes = self.return_window_bytes.saturating_add(bytes as u64);
        true
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.missing_tracker.missing_sequences().collect()
    }

    pub fn stats(&self) -> ReceiverStats {
        let mut stats = self.stats;
        stats.apply_tracker_counters(self.missing_tracker.counters());
        stats.rtt_micros = self.rtt.srtt_micros();
        stats.rtt_min_micros = self.rtt.min_micros();
        stats
    }

    pub fn handle_rtcp(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.handle_rtcp_at(packet, ntp_now())
    }

    pub fn handle_rtcp_at(&mut self, packet: &[u8], now_ntp: u64) -> Result<Vec<Vec<u8>>> {
        let mut responses = Vec::new();
        for packet in decode_compound(packet)? {
            match packet {
                RtcpPacket::SenderReport(report) => {
                    self.peer_ssrc = Some(report.ssrc);
                    self.last_sender_report = Some((report.ntp_timestamp, now_ntp));
                }
                RtcpPacket::Echo(Echo {
                    ssrc,
                    ntp_timestamp,
                    kind: EchoKind::Request,
                }) => {
                    let mut response = self.build_receiver_report(now_ntp);
                    encode_echo(
                        Echo {
                            ssrc,
                            ntp_timestamp,
                            kind: EchoKind::Response { delay: 0 },
                        },
                        &mut response,
                    );
                    responses.push(response);
                }
                RtcpPacket::Echo(Echo {
                    ntp_timestamp,
                    kind: EchoKind::Response { delay },
                    ..
                }) if self.tuning.measure_rtt && ntp_timestamp <= now_ntp => {
                    let rtt = calculate_rtt_micros(ntp_timestamp, now_ntp, delay);
                    if rtt <= MAX_RTT_SAMPLE_MICROS {
                        self.rtt.sample(rtt);
                        self.stats.rtt_samples_echo += 1;
                    }
                }
                _ => {}
            }
        }
        Ok(responses)
    }

    fn encode_receiver_report(&self, now_ntp: u64, out: &mut Vec<u8>) {
        encode_receiver_report(self.receiver_report(now_ntp), out);
        encode_sdes_cname(self.flow_id, &self.cname, out);
    }

    fn receiver_report(&self, now_ntp: u64) -> ReceiverReport {
        let base_sequence = self.base_sequence.unwrap_or(0);
        let highest_sequence = self.highest_sequence.unwrap_or(0);
        let expected_packets = if self.highest_sequence.is_some() {
            u64::from(highest_sequence.wrapping_sub(base_sequence)) + 1
        } else {
            0
        };
        let received_unique = self
            .stats
            .received_packets
            .saturating_sub(self.stats.duplicate_packets);
        let cumulative_loss = expected_packets.saturating_sub(received_unique);
        let fraction_lost = cumulative_loss
            .saturating_mul(256)
            .checked_div(expected_packets)
            .unwrap_or(0)
            .min(255) as u8;
        let (last_sender_report, delay_since_last_sender_report) =
            self.last_sender_report
                .map_or((0, 0), |(sr_ntp, received_ntp)| {
                    let lsr = ((sr_ntp >> 16) & 0xffff_ffff) as u32;
                    let dlsr = (now_ntp.saturating_sub(received_ntp) >> 16).min(u64::from(u32::MAX))
                        as u32;
                    (lsr, dlsr)
                });

        ReceiverReport {
            ssrc: self.flow_id,
            recv_ssrc: self.peer_ssrc.unwrap_or(self.flow_id),
            fraction_lost,
            cumulative_packet_loss: cumulative_loss.min(0x00ff_ffff) as u32,
            highest_sequence,
            jitter: 0,
            last_sender_report,
            delay_since_last_sender_report,
        }
    }
}

/// Smallest payload assumed when sizing the receiver's duplicate-detection
/// ring: seven 188-byte MPEG-TS packets, the usual RIST datagram.
const RECEIVER_WINDOW_PAYLOAD_FLOOR: u128 = 7 * 188;
const MIN_RECEIVER_WINDOW_PACKETS: u128 = 1_024;
const MAX_RECEIVER_RING_PACKETS: u128 = 32_768;

fn recovery_window_packets(config: &RecoveryConfig) -> usize {
    // max_bitrate is expressed in kbit/s. The ring only tells duplicates from
    // late packets; holes are tracked separately up to the 16-bit NACK
    // horizon whatever its size, so it no longer drives CPU or hole safety.
    let bits = u128::from(config.max_bitrate)
        .saturating_mul(1_000)
        .saturating_mul(effective_recovery_age(config).as_millis());
    let packets = bits
        .saturating_div(8)
        .saturating_div(RECEIVER_WINDOW_PAYLOAD_FLOOR)
        .saturating_div(1_000)
        .clamp(MIN_RECEIVER_WINDOW_PACKETS, MAX_RECEIVER_RING_PACKETS);
    usize::try_from(packets).unwrap_or(MAX_RECEIVER_RING_PACKETS as usize)
}

fn default_receiver_tracker() -> MissingTracker {
    let recovery = RecoveryConfig::default();
    let mut tracker = MissingTracker::with_limits(
        recovery_window_packets(&recovery),
        effective_recovery_age(&recovery),
    );
    tracker.set_initial_nack_delay(recovery.reorder_buffer);
    tracker
}

fn effective_recovery_age(config: &RecoveryConfig) -> Duration {
    config.length_min
        + config
            .length_max
            .saturating_sub(config.length_min)
            .div_f64(2.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use crate::packet::rtp::{encode_packet, RtpHeader, RIST_RTP_EXTENSION_NPD_FLAG};
    use crate::time::ntp_from_unix_duration;
    use std::time::Duration;

    #[test]
    fn sends_and_receives_payload_without_io() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let packet = sender.send_payload(b"payload", ntp, now);
        let received = receiver.accept_packet(&packet.bytes).unwrap();
        assert_eq!(received.sequence, 0);
        assert_eq!(received.payload, b"payload");
        assert!(received.newly_missing.is_empty());
    }

    #[test]
    fn rejects_non_mpegts_rtp_payload_type() {
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let mut header = RtpHeader::new_mpegts(0, 90_000, 0x1122_3344);
        header.payload_type = 72;
        let packet = encode_packet(header, b"not mpeg-ts");

        let err = receiver.accept_packet(&packet).unwrap_err();
        assert_eq!(err, crate::Error::UnsupportedRtpPayloadType(72));
    }

    #[test]
    fn detects_loss_and_retransmits_from_feedback() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let first = sender.send_payload(b"first", ntp, now);
        let lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);

        receiver.accept_packet(&first.bytes).unwrap();
        let observed = receiver.accept_packet(&third.bytes).unwrap();
        assert_eq!(observed.newly_missing, vec![1]);

        let feedback = receiver.build_feedback();
        let retries = sender.handle_feedback(&feedback).unwrap();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].sequence, lost.sequence);
        assert!(retries[0].retry);
        assert_eq!(sender.stats().feedback_packets, 1);
        assert_eq!(sender.stats().retransmitted_packets, 1);

        let recovered = receiver.accept_packet(&retries[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
        assert_eq!(receiver.stats().total_missing_packets, 1);
        assert_eq!(receiver.stats().currently_missing_packets, 0);
        assert_eq!(receiver.stats().recovered_packets, 1);
    }

    #[test]
    fn sender_suppresses_null_packets_when_enabled() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64).with_null_packet_suppression(true);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let mut payload = Vec::new();
        payload.extend_from_slice(&ts_packet(0x0100, b"first"));
        payload.extend_from_slice(&ts_packet(TS_NULL_PID, b""));
        payload.extend_from_slice(&ts_packet(0x0101, b"third"));

        let packet = sender.send_payload(&payload, ntp, now);
        let decoded = RtpPacket::decode(&packet.bytes).unwrap();
        let extension = decoded.extension.unwrap();
        assert_eq!(extension.flags, RIST_RTP_EXTENSION_NPD_FLAG);
        assert_eq!(extension.npd_bits, 1 << 5);
        assert_eq!(decoded.payload.len(), TS_PACKET_SIZE * 2);

        let received = receiver.accept_packet(&packet.bytes).unwrap();
        assert_eq!(received.payload, payload);
    }

    #[test]
    fn echo_response_updates_sender_rtt() {
        let request_ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let response_ntp =
            ntp_from_unix_duration(Duration::from_secs(1) + Duration::from_millis(7));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let request = sender.build_echo_request(request_ntp);
        let responses = receiver.handle_rtcp(&request).unwrap();
        assert_eq!(responses.len(), 1);

        let retries = sender
            .handle_feedback_at(&responses[0], response_ntp)
            .unwrap();
        assert!(retries.is_empty());
        assert_eq!(sender.stats().rtt_micros, Some(7_000));
    }

    #[test]
    fn sender_peer_states_isolate_retry_limits_and_rtt() {
        let start = Instant::now();
        let request_ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut recovery = RecoveryConfig {
            max_retries: 1,
            max_bitrate: 100_000,
            ..RecoveryConfig::default()
        };
        recovery.length_min = Duration::from_secs(1);
        recovery.length_max = Duration::from_secs(1);
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64)
            .with_recovery_config(recovery, CongestionControlMode::Off);
        let packet = sender.send_payload(b"shared-history", request_ntp, start);
        let mut peer_a = sender.new_peer_state();
        let mut peer_b = sender.new_peer_state();

        assert_eq!(
            sender
                .retransmit_for_peer_at(&mut peer_a, &[packet.sequence], start)
                .len(),
            1
        );
        assert_eq!(
            sender
                .retransmit_for_peer_at(&mut peer_b, &[packet.sequence], start)
                .len(),
            1
        );
        assert!(sender
            .retransmit_for_peer_at(&mut peer_a, &[packet.sequence], start)
            .is_empty());
        assert_eq!(peer_a.stats().retransmitted_packets, 1);
        assert_eq!(peer_b.stats().retransmitted_packets, 1);

        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let response = receiver
            .handle_rtcp(&sender.build_echo_request(request_ntp))
            .unwrap()
            .remove(0);
        sender
            .handle_feedback_for_peer_at(
                &mut peer_a,
                &response,
                request_ntp + (7_u64 << 32) / 1_000,
                start,
            )
            .unwrap();
        sender
            .handle_feedback_for_peer_at(
                &mut peer_b,
                &response,
                request_ntp + (20_u64 << 32) / 1_000,
                start,
            )
            .unwrap();

        assert_eq!(peer_a.stats().rtt_micros, Some(7_000));
        assert_eq!(peer_b.stats().rtt_micros, Some(20_000));
    }

    #[test]
    fn receiver_feedback_includes_full_receiver_report() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x5566_7788, "rust", NackMode::Range);

        let first = sender.send_payload(b"first", ntp, now);
        let _lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);

        receiver.accept_packet(&first.bytes).unwrap();
        receiver.accept_packet(&third.bytes).unwrap();

        let feedback = receiver.build_feedback_at(ntp);
        assert_eq!(decode_nacks_from_compound(&feedback).unwrap(), vec![1]);
        assert_eq!(
            decode_compound(&feedback).unwrap(),
            vec![
                RtcpPacket::ReceiverReport(ReceiverReport {
                    ssrc: 0x5566_7788,
                    recv_ssrc: 0x1122_3344,
                    fraction_lost: 85,
                    cumulative_packet_loss: 1,
                    highest_sequence: 2,
                    jitter: 0,
                    last_sender_report: 0,
                    delay_since_last_sender_report: 0,
                }),
                RtcpPacket::SourceDescription {
                    ssrc: 0x5566_7788,
                    cname: "rust".to_string(),
                },
                RtcpPacket::Nack(vec![1]),
            ]
        );
    }

    #[test]
    fn sender_polls_scheduled_sender_report_and_echo() {
        let start = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let intervals = RtcpIntervals {
            feedback: Duration::from_millis(20),
            report: Duration::from_millis(10),
            echo: Duration::from_millis(10),
        };
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64).with_rtcp_intervals(intervals);

        assert_eq!(sender.poll_rtcp(start, ntp), None);
        let packet = sender
            .poll_rtcp(start + Duration::from_millis(10), ntp)
            .unwrap();

        assert_eq!(
            decode_compound(&packet).unwrap(),
            vec![
                RtcpPacket::SenderReport(SenderReport {
                    ssrc: 0x1122_3344,
                    ntp_timestamp: ntp,
                    rtp_timestamp: mpegts_rtp_timestamp(ntp),
                    sender_packets: 0,
                    sender_bytes: 0,
                }),
                RtcpPacket::SourceDescription {
                    ssrc: 0x1122_3344,
                    cname: "rust".to_string(),
                },
                RtcpPacket::Echo(Echo {
                    ssrc: 0x1122_3344,
                    ntp_timestamp: ntp,
                    kind: EchoKind::Request,
                }),
            ]
        );
    }

    const FLOW: u32 = 0x1122_3344;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn data(sequence: u32) -> Vec<u8> {
        encode_packet(RtpHeader::new_mpegts(sequence as u16, 0, FLOW), b"ts")
    }

    fn retry_data(sequence: u32) -> Vec<u8> {
        encode_packet(RtpHeader::new_mpegts(sequence as u16, 0, FLOW | 1), b"ts")
    }

    /// A receiver with `tuning` that saw 0 and 2 (hole 1) at `t0`.
    fn receiver_with_hole(
        tuning: RecoveryTuning,
        recovery: RecoveryConfig,
    ) -> (SimpleReceiverCore, Instant) {
        let t0 = Instant::now();
        let mut receiver = SimpleReceiverCore::new(FLOW, "rust", NackMode::Range)
            .with_recovery_config(recovery, CongestionControlMode::Normal)
            .with_recovery_tuning(tuning);
        receiver.accept_packet_at(&data(0), t0).unwrap();
        receiver.accept_packet_at(&data(2), t0).unwrap();
        (receiver, t0)
    }

    /// Polls every millisecond from `from` to `to` (inclusive) and returns
    /// the millisecond offsets from `t0` at which a NACK for `sequence` went
    /// out.
    fn nack_times(
        receiver: &mut SimpleReceiverCore,
        t0: Instant,
        from: u64,
        to: u64,
        sequence: u32,
    ) -> Vec<u64> {
        let mut times = Vec::new();
        for offset in from..=to {
            let mut packets = Vec::new();
            receiver.poll_rtcp_into(t0 + ms(offset), 0, &mut packets, 64);
            if packets.iter().any(|packet| {
                decode_nacks_from_compound(packet)
                    .unwrap()
                    .contains(&sequence)
            }) {
                times.push(offset);
            }
        }
        times
    }

    fn echo_response(request_ntp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_empty_receiver_report(FLOW, &mut out);
        encode_echo(
            Echo {
                ssrc: FLOW,
                ntp_timestamp: request_ntp,
                kind: EchoKind::Response { delay: 0 },
            },
            &mut out,
        );
        out
    }

    /// Feeds one echo RTT sample of `rtt` to `receiver`.
    fn learn_rtt(receiver: &mut SimpleReceiverCore, rtt: Duration) {
        let sent = ntp_from_unix_duration(Duration::from_secs(100));
        let back = ntp_from_unix_duration(Duration::from_secs(100) + rtt);
        receiver.handle_rtcp_at(&echo_response(sent), back).unwrap();
    }

    fn fixed_first_nack() -> RecoveryTuning {
        RecoveryTuning::librist_like()
    }

    #[test]
    fn nack_due_at_1ms_poll_not_20ms_grid() {
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), RecoveryConfig::default());
        // reorder_buffer 15 ms: the first poll at or after t0 + 15 ms sends it.
        assert_eq!(nack_times(&mut receiver, t0, 0, 15, 1), vec![15]);
        assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, 1);
    }

    #[test]
    fn renack_uses_measured_rtt() {
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), RecoveryConfig::default());
        learn_rtt(&mut receiver, ms(30));
        assert_eq!(receiver.stats().rtt_micros, Some(30_000));
        // 1.1 x 30 ms + 1 ms margin = 34 ms between attempts, not rtt_min 5.
        assert_eq!(
            nack_times(&mut receiver, t0, 0, 120, 1),
            vec![15, 49, 83, 117]
        );
    }

    #[test]
    fn renack_clamps_the_measured_rtt_to_rtt_min_and_rtt_max() {
        let recovery = RecoveryConfig {
            rtt_max: ms(20),
            ..RecoveryConfig::default()
        };
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), recovery);
        learn_rtt(&mut receiver, ms(1));
        // clamp(1, 5, 20) = 5: 5.5 + 1 = 6.5 ms between attempts.
        assert_eq!(nack_times(&mut receiver, t0, 0, 30, 1), vec![15, 22, 29]);
        learn_rtt(&mut receiver, ms(400));
        // max(srtt, last) = 400, clamped to rtt_max 20: 23 ms.
        assert_eq!(nack_times(&mut receiver, t0, 31, 60, 1), vec![36, 59]);
    }

    #[test]
    fn unmeasured_rtt_backs_off() {
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), RecoveryConfig::default());
        // No RTT sample: 6.5 ms, then 13, 26, 52 ms after each attempt.
        assert_eq!(
            nack_times(&mut receiver, t0, 0, 200, 1),
            vec![15, 22, 35, 61, 113]
        );
        assert!(receiver.stats().echo_requests_sent > 0);
        assert_eq!(receiver.stats().rtt_micros, None);
    }

    #[test]
    fn without_rtt_measurement_renacks_follow_rtt_min_without_backoff() {
        let tuning = RecoveryTuning {
            measure_rtt: false,
            ..fixed_first_nack()
        };
        let (mut receiver, t0) = receiver_with_hole(tuning, RecoveryConfig::default());
        learn_rtt(&mut receiver, ms(30));
        assert_eq!(receiver.stats().rtt_micros, None, "echo ignored");
        assert_eq!(nack_times(&mut receiver, t0, 0, 30, 1), vec![15, 22, 29]);
        assert_eq!(receiver.stats().echo_requests_sent, 0);
    }

    #[test]
    fn no_nack_after_deadline() {
        let recovery = RecoveryConfig {
            length_min: ms(100),
            length_max: ms(100),
            ..RecoveryConfig::default()
        };
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), recovery);
        learn_rtt(&mut receiver, ms(30));
        // 15 and 49 can bring a repair back before 100 ms; at 83 only 17 ms
        // are left, less than one RTT, so the hole is given up.
        assert_eq!(nack_times(&mut receiver, t0, 0, 99, 1), vec![15, 49]);
        assert_eq!(receiver.stats().nack_too_late, 1);
    }

    #[test]
    fn nack_packets_respect_the_feedback_gap() {
        let t0 = Instant::now();
        let mut receiver = SimpleReceiverCore::new(FLOW, "rust", NackMode::Range)
            .with_recovery_tuning(fixed_first_nack());
        receiver.accept_packet_at(&data(0), t0).unwrap();
        receiver.accept_packet_at(&data(2), t0).unwrap();
        receiver
            .accept_packet_at(&data(4), t0 + Duration::from_micros(500))
            .unwrap();
        let mut sent = Vec::new();
        for offset_us in (15_000..=16_000).step_by(500) {
            let mut packets = Vec::new();
            receiver.poll_rtcp_into(t0 + Duration::from_micros(offset_us), 0, &mut packets, 64);
            for packet in packets {
                for sequence in decode_nacks_from_compound(&packet).unwrap() {
                    sent.push((offset_us, sequence));
                }
            }
        }
        // Hole 3 is due at 15.5 ms but waits for the 1 ms gap.
        assert_eq!(sent, vec![(15_000, 1), (16_000, 3)]);
    }

    #[test]
    fn receiver_sends_echo_and_learns_rtt() {
        let t0 = Instant::now();
        let base = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(FLOW, 64);
        let mut receiver = SimpleReceiverCore::new(FLOW, "rust", NackMode::Range);
        assert_eq!(receiver.next_poll_at(), None, "nothing before data");
        let packet = sender.send_payload(b"x", base, t0);
        receiver.accept_packet_at(&packet.bytes, t0).unwrap();
        // The first echo request goes out with the first report, at once.
        assert_eq!(receiver.next_poll_at(), Some(t0));
        let request = receiver.poll_rtcp(t0, base).unwrap();
        assert!(decode_compound(&request)
            .unwrap()
            .contains(&RtcpPacket::Echo(Echo {
                ssrc: FLOW,
                ntp_timestamp: base,
                kind: EchoKind::Request,
            })));
        let response = sender
            .handle_feedback_outcome_at(&request, base, t0)
            .unwrap()
            .responses
            .remove(0);
        let back = ntp_from_unix_duration(Duration::from_secs(1) + ms(30));
        receiver.handle_rtcp_at(&response, back).unwrap();
        let stats = receiver.stats();
        assert_eq!(stats.rtt_micros, Some(30_000));
        assert_eq!(stats.rtt_min_micros, Some(30_000));
        assert_eq!(stats.rtt_samples_echo, 1);
        assert_eq!(stats.echo_requests_sent, 1);
        // The next one is due one echo interval later.
        assert_eq!(receiver.poll_rtcp(t0 + ms(99), base), None);
        assert_eq!(
            receiver.next_poll_at(),
            Some(t0 + DEFAULT_RTCP_ECHO_INTERVAL)
        );
    }

    #[test]
    fn echo_request_rides_on_a_due_nack() {
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), RecoveryConfig::default());
        receiver.next_echo_at = Some(t0 + ms(15));
        let packet = receiver.poll_rtcp(t0 + ms(15), 7).unwrap();
        let decoded = decode_compound(&packet).unwrap();
        assert_eq!(decode_nacks_from_compound(&packet).unwrap(), vec![1]);
        assert!(decoded.contains(&RtcpPacket::Echo(Echo {
            ssrc: FLOW,
            ntp_timestamp: 7,
            kind: EchoKind::Request,
        })));
        assert_eq!(receiver.stats().echo_requests_sent, 1);
    }

    fn adaptive_tuning() -> RecoveryTuning {
        RecoveryTuning {
            adaptive_first_nack: true,
            ..RecoveryTuning::librist_like()
        }
    }

    #[test]
    fn first_nack_delay_adapts_to_observed_reorder() {
        let (mut receiver, t0) = receiver_with_hole(adaptive_tuning(), RecoveryConfig::default());
        // No reordering seen: the floor of 2 ms, not reorder_buffer 15 ms.
        assert_eq!(receiver.next_poll_at(), Some(t0));
        assert_eq!(nack_times(&mut receiver, t0, 1, 3, 1), vec![2]);
        assert_eq!(receiver.stats().first_nack_delay_micros, 2_000);
        // The sender marks its repairs: every unmarked arrival is an original.
        assert!(
            receiver
                .accept_packet_at(&retry_data(1), t0 + ms(4))
                .unwrap()
                .recovered
        );

        // Packet 4 arrives 6 ms after 5 revealed it missing (and after a
        // spurious NACK at 2 ms): reordering of 6 ms.
        let t1 = t0 + ms(10);
        receiver.accept_packet_at(&data(3), t1).unwrap();
        receiver.accept_packet_at(&data(5), t1).unwrap();
        assert_eq!(nack_times(&mut receiver, t0, 11, 13, 4), vec![12]);
        assert!(
            receiver
                .accept_packet_at(&data(4), t1 + ms(6))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().reorder_samples, 1);
        // 1.5 x 6 + 1 = 10 ms.
        assert_eq!(receiver.first_nack_delay(t1 + ms(6)), ms(10));
        // It decays with a 10 s half-life: 1.5 x 3 + 1 = 5.5 ms.
        assert_eq!(
            receiver.first_nack_delay(t1 + ms(6) + Duration::from_secs(10)),
            Duration::from_micros(5_500)
        );
        // Never above reorder_buffer.
        receiver.reorder.sample(ms(50), t1 + ms(7));
        assert_eq!(receiver.first_nack_delay(t1 + ms(7)), ms(15));
    }

    #[test]
    fn reorder_ignores_retry_marked_repairs() {
        let (mut receiver, t0) = receiver_with_hole(adaptive_tuning(), RecoveryConfig::default());
        assert_eq!(nack_times(&mut receiver, t0, 0, 3, 1), vec![2]);
        // The repair arrives 30 ms after detection: not reordering.
        assert!(
            receiver
                .accept_packet_at(&retry_data(1), t0 + ms(30))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().reorder_samples, 0);
        assert_eq!(receiver.first_nack_delay(t0 + ms(30)), ms(2));
    }

    #[test]
    fn unmarked_late_arrival_after_a_nack_is_ambiguous_until_retries_are_marked() {
        // A sender that does not mark retries (rist-rs before P7): an
        // arrival long after our NACK may be the repair, so no sample.
        let (mut receiver, t0) = receiver_with_hole(adaptive_tuning(), RecoveryConfig::default());
        assert_eq!(nack_times(&mut receiver, t0, 0, 3, 1), vec![2]);
        assert!(
            receiver
                .accept_packet_at(&data(1), t0 + ms(30))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().reorder_samples, 0);
        // An original before any NACK is always a sample.
        receiver.accept_packet_at(&data(4), t0 + ms(31)).unwrap();
        assert!(
            receiver
                .accept_packet_at(&data(3), t0 + ms(32))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().reorder_samples, 1);
        assert_eq!(
            receiver.first_nack_delay(t0 + ms(32)),
            Duration::from_micros(2_500)
        );
    }

    fn redundant_tuning() -> RecoveryTuning {
        RecoveryTuning {
            redundant_nacks: true,
            ..RecoveryTuning::librist_like()
        }
    }

    #[test]
    fn redundant_nack_is_not_counted_as_attempt() {
        let (mut receiver, t0) = receiver_with_hole(redundant_tuning(), RecoveryConfig::default());
        learn_rtt(&mut receiver, ms(30));
        // Copy gap 30 / 20 = 1.5 ms; next attempt 1.1 x 30 + 1 + 1.5 = 35.5
        // ms after the first.
        assert_eq!(
            nack_times(&mut receiver, t0, 0, 60, 1),
            vec![15, 17, 51, 53]
        );
        let stats = receiver.stats();
        assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, 2);
        assert_eq!(stats.nack_entries_sent, 2);
        assert_eq!(stats.nack_copies_sent, 2);
        assert_eq!(stats.nack_packets, 4);
    }

    #[test]
    fn no_nack_copies_with_congestion_control_off_or_a_tiny_rtt() {
        let (mut receiver, t0) = receiver_with_hole(redundant_tuning(), RecoveryConfig::default());
        receiver.congestion_control = CongestionControlMode::Off;
        learn_rtt(&mut receiver, ms(30));
        assert_eq!(nack_times(&mut receiver, t0, 0, 50, 1), vec![15, 49]);
        let recovery = RecoveryConfig {
            rtt_min: ms(1),
            ..RecoveryConfig::default()
        };
        let (mut receiver, t0) = receiver_with_hole(redundant_tuning(), recovery);
        learn_rtt(&mut receiver, ms(1));
        // A 1 ms copy gap would not stay below the sender's spacing.
        assert_eq!(nack_times(&mut receiver, t0, 0, 20, 1), vec![15, 18]);
        assert_eq!(receiver.stats().nack_copies_sent, 0);
    }

    #[test]
    fn spacing_refuses_copy_accepts_next_attempt() {
        let start = Instant::now();
        let base = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(FLOW, 64);
        // The sender measured 1.05 x the receiver's RTT.
        let request = sender.build_echo_request(base);
        let mut echo_peer = SimpleReceiverCore::new(FLOW, "rust", NackMode::Range);
        let response = echo_peer.handle_rtcp_at(&request, base).unwrap().remove(0);
        sender
            .handle_feedback_outcome_at(&response, base + (31_500u64 << 32) / 1_000_000, start)
            .unwrap();
        assert_eq!(sender.stats().rtt_micros, Some(31_500));
        let t0 = start;
        for index in 0..3_u32 {
            sender.send_payload(&index.to_be_bytes(), base, t0);
        }
        let mut receiver = SimpleReceiverCore::new(FLOW, "rust", NackMode::Range)
            .with_recovery_tuning(redundant_tuning());
        receiver.accept_packet_at(&data(0), t0).unwrap();
        receiver.accept_packet_at(&data(2), t0).unwrap();
        learn_rtt(&mut receiver, ms(30));
        let mut served = Vec::new();
        for offset in 0..=60 {
            let now = t0 + ms(offset);
            let mut packets = Vec::new();
            receiver.poll_rtcp_into(now, base, &mut packets, 64);
            for packet in packets {
                if decode_nacks_from_compound(&packet).unwrap().is_empty() {
                    continue;
                }
                let outcome = sender
                    .handle_feedback_outcome_at(&packet, base, now)
                    .unwrap();
                served.push((offset, outcome.retries.len()));
            }
        }
        // Each copy is refused because its attempt arrived; the next
        // attempt clears the 0.9 x 31.5 ms spacing.
        assert_eq!(served, vec![(15, 1), (17, 0), (51, 1), (53, 0)]);
        assert_eq!(sender.stats().retransmit_refused_spacing, 2);

        // When an attempt is lost, its copy is the first request: served.
        let mut lonely = SimpleSenderCore::new(FLOW, 64);
        for index in 0..3_u32 {
            lonely.send_payload(&index.to_be_bytes(), base, t0);
        }
        assert_eq!(lonely.retransmit_at(&[1], t0 + ms(17)).len(), 1);
    }

    #[test]
    fn karn_sample_only_first_attempt_retry_flag() {
        let (mut receiver, t0) = receiver_with_hole(fixed_first_nack(), RecoveryConfig::default());
        receiver.accept_packet_at(&data(4), t0).unwrap();
        receiver.accept_packet_at(&data(6), t0).unwrap();
        // Holes 1, 3 and 5 are NACKed once at 15 ms.
        let mut packets = Vec::new();
        receiver.poll_rtcp_into(t0 + ms(15), 0, &mut packets, 64);
        // A retry-marked repair of hole 1, 7 ms after its single NACK.
        assert!(
            receiver
                .accept_packet_at(&retry_data(1), t0 + ms(22))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().rtt_samples_karn, 1);
        assert_eq!(receiver.rtt().last_micros(), Some(7_000));
        // An unmarked arrival of hole 3: an original, not a sample.
        assert!(
            receiver
                .accept_packet_at(&data(3), t0 + ms(23))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().rtt_samples_karn, 1);
        // Hole 5 NACKed a second time: its repair is ambiguous.
        receiver.poll_rtcp_into(t0 + ms(40), 0, &mut packets, 64);
        assert_eq!(receiver.missing_tracker.hole(5).unwrap().nack_count, 2);
        assert!(
            receiver
                .accept_packet_at(&retry_data(5), t0 + ms(45))
                .unwrap()
                .recovered
        );
        assert_eq!(receiver.stats().rtt_samples_karn, 1);
        assert_eq!(receiver.stats().retry_packets_received, 2);
    }

    #[test]
    fn retransmission_policy_enforces_spacing_age_retry_and_bitrate_limits() {
        let start = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut recovery = RecoveryConfig {
            length_min: Duration::from_millis(100),
            length_max: Duration::from_millis(100),
            rtt_min: Duration::from_millis(10),
            rtt_max: Duration::from_millis(10),
            max_retries: 1,
            max_bitrate: 100_000,
            ..RecoveryConfig::default()
        };
        let mut sender = SimpleSenderCore::new(1, 8)
            .with_recovery_config(recovery.clone(), CongestionControlMode::Normal);
        let packet = sender.send_payload(b"payload", ntp, start);

        assert_eq!(sender.retransmit_at(&[packet.sequence], start).len(), 1);
        assert!(sender
            .retransmit_at(&[packet.sequence], start + Duration::from_millis(10))
            .is_empty());

        recovery.max_retries = 20;
        recovery.max_bitrate = 1;
        let mut bitrate_limited = SimpleSenderCore::new(1, 8)
            .with_recovery_config(recovery.clone(), CongestionControlMode::Off);
        let large = bitrate_limited.send_payload(&vec![0; 256], ntp, start);
        assert!(bitrate_limited
            .retransmit_at(&[large.sequence], start)
            .is_empty());

        recovery.max_bitrate = 100_000;
        let mut expired = SimpleSenderCore::new(1, 8)
            .with_recovery_config(recovery.clone(), CongestionControlMode::Off);
        let old = expired.send_payload(b"old", ntp, start);
        expired.send_payload(b"successor", ntp, start);
        // Older than L + 2 x rtt_min (120 ms) and its successor older than
        // L + rtt + 5 ms (115 ms).
        assert!(expired
            .retransmit_at(&[old.sequence], start + Duration::from_millis(121))
            .is_empty());

        // Every refusal is counted by reason.
        assert_eq!(sender.stats().nack_requests, 2);
        assert_eq!(sender.stats().retransmit_refused_max_retries, 1);
        assert_eq!(bitrate_limited.stats().retransmit_refused_bitrate, 1);
        assert_eq!(expired.stats().retransmit_refused_too_old, 1);
        assert!(expired
            .retransmit_at(&[old.sequence + 50], start)
            .is_empty());
        assert_eq!(expired.stats().retransmit_refused_not_in_history, 1);
        assert_eq!(expired.stats().nack_requests, 2);

        let mut spaced = SimpleSenderCore::new(1, 8)
            .with_recovery_config(recovery, CongestionControlMode::Normal);
        let packet = spaced.send_payload(b"spaced", ntp, start);
        assert_eq!(spaced.retransmit_at(&[packet.sequence], start).len(), 1);
        assert!(spaced
            .retransmit_at(&[packet.sequence], start + Duration::from_millis(5))
            .is_empty());
        let stats = spaced.stats();
        assert_eq!(stats.retransmit_refused_spacing, 1);
        assert_eq!(stats.retransmitted_packets, 1);
        assert_eq!(stats.sent_packets, 1);

        assert!(spaced.handle_feedback_at(&[0x80, 201, 0], ntp).is_err());
        assert_eq!(spaced.stats().feedback_decode_errors, 1);
        assert_eq!(spaced.stats().feedback_packets, 1);
    }

    fn frame_sender(length_ms: u64) -> SimpleSenderCore {
        let recovery = RecoveryConfig {
            length_min: ms(length_ms),
            length_max: ms(length_ms),
            ..RecoveryConfig::default()
        };
        SimpleSenderCore::new(FLOW, 64)
            .with_recovery_config(recovery, CongestionControlMode::Normal)
    }

    #[test]
    fn sender_age_by_successor_serves_frame_tail() {
        let t = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        // L 40 ms, rtt_min 5: the tail of one frame, the next frame 40 ms
        // later, the tail NACK 17 ms after that (reorder 15 + RTT 1 + poll).
        let mut sender = frame_sender(40);
        let tail = sender.send_payload(b"tail", ntp, t);
        sender.send_payload(b"next frame", ntp, t + ms(40));
        assert_eq!(sender.retransmit_at(&[tail.sequence], t + ms(57)).len(), 1);

        // The same NACK once the successor is older than L + rtt + 5 ms
        // (40 + 5 + 5): the receiver gave up on it, so it is refused.
        let mut sender = frame_sender(40);
        let tail = sender.send_payload(b"tail", ntp, t);
        sender.send_payload(b"next frame", ntp, t + ms(40));
        assert!(sender
            .retransmit_at(&[tail.sequence], t + ms(40 + 40 + 5 + 6))
            .is_empty());
        assert_eq!(sender.stats().retransmit_refused_too_old, 1);
    }

    #[test]
    fn sender_serves_retry_up_to_l_plus_two_rtt_min() {
        let t = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        // A packet in the middle of a burst: successor sent at once. Up to
        // L + 2 x rtt_min (50 ms) it is served whatever the successor says.
        let mut sender = frame_sender(40);
        let packet = sender.send_payload(b"mid", ntp, t);
        sender.send_payload(b"next", ntp, t);
        assert_eq!(
            sender.retransmit_at(&[packet.sequence], t + ms(50)).len(),
            1
        );
        let mut sender = frame_sender(40);
        let packet = sender.send_payload(b"mid", ntp, t);
        sender.send_payload(b"next", ntp, t);
        assert!(sender
            .retransmit_at(&[packet.sequence], t + ms(51))
            .is_empty());
        // The newest packet has no successor yet: nobody can have found it
        // missing by sequence, so it is served at any age.
        let mut sender = frame_sender(40);
        let newest = sender.send_payload(b"newest", ntp, t);
        assert_eq!(
            sender.retransmit_at(&[newest.sequence], t + ms(500)).len(),
            1
        );
    }

    #[test]
    fn history_grows_to_keep_packets_for_l_plus_two_rtt_max() {
        let t = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let recovery = RecoveryConfig {
            length_min: ms(40),
            length_max: ms(40),
            rtt_max: ms(20),
            ..RecoveryConfig::default()
        };
        // 8 slots, but 1000 packets sent within the 80 ms retention.
        let mut sender = SimpleSenderCore::new(FLOW, 8)
            .with_recovery_config(recovery.clone(), CongestionControlMode::Normal);
        for index in 0..1_000_u32 {
            sender.send_payload(
                &index.to_be_bytes(),
                ntp,
                t + Duration::from_micros(u64::from(index) * 50),
            );
        }
        assert_eq!(sender.history_capacity(), 1_024);
        let now = t + ms(45);
        assert_eq!(sender.retransmit_at(&[0, 500, 999], now).len(), 3);
        // Beyond the retention the history evicts again instead of growing.
        for index in 1_000..3_000_u32 {
            sender.send_payload(
                &index.to_be_bytes(),
                ntp,
                t + ms(200) + Duration::from_micros(u64::from(index)),
            );
        }
        assert_eq!(sender.history_capacity(), 2_048);

        // With history_by_time off the fixed count of 8 is kept.
        let mut fixed = SimpleSenderCore::new(FLOW, 8)
            .with_recovery_config(recovery.clone(), CongestionControlMode::Normal)
            .with_recovery_tuning(RecoveryTuning {
                history_by_time: false,
                ..RecoveryTuning::default()
            });
        for index in 0..100_u32 {
            fixed.send_payload(&index.to_be_bytes(), ntp, t);
        }
        assert_eq!(fixed.history_capacity(), 8);
        assert!(fixed.retransmit_at(&[0], t).is_empty());
        assert_eq!(fixed.stats().retransmit_refused_not_in_history, 1);

        // And never beyond max_history_packets.
        let mut capped = SimpleSenderCore::new(FLOW, 8)
            .with_recovery_config(recovery, CongestionControlMode::Normal)
            .with_recovery_tuning(RecoveryTuning {
                max_history_packets: 100,
                ..RecoveryTuning::default()
            });
        for index in 0..1_000_u32 {
            capped.send_payload(&index.to_be_bytes(), ntp, t);
        }
        assert_eq!(capped.history_capacity(), 128);
    }

    #[test]
    fn retry_spacing_survives_history_growth() {
        let t = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(FLOW, 8);
        for index in 0..4_u32 {
            sender.send_payload(&index.to_be_bytes(), ntp, t);
        }
        assert_eq!(sender.retransmit_at(&[1], t).len(), 1);
        // The history grows to 16 while sequence 1 is spaced.
        for index in 4..16_u32 {
            sender.send_payload(&index.to_be_bytes(), ntp, t);
        }
        assert_eq!(sender.history_capacity(), 16);
        assert!(sender.retransmit_at(&[1], t + ms(1)).is_empty());
        assert_eq!(sender.stats().retransmit_refused_spacing, 1);
        // 9 shared sequence 1's old slot; it has its own now.
        assert_eq!(sender.retransmit_at(&[9], t + ms(1)).len(), 1);
    }

    #[test]
    fn malformed_npd_map_delivers_the_original_rtp_payload() {
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let header = RtpHeader::new_mpegts(0, 90_000, 1);
        let packet = encode_packet_with_extension(
            header,
            RistRtpExtension::new_npd(1 << 6),
            b"valid-opaque-payload",
        );
        let received = receiver.accept_packet(&packet).unwrap();
        assert_eq!(received.payload, b"valid-opaque-payload");
    }

    #[test]
    fn bounded_recovery_repairs_zero_to_twenty_five_percent_loss_with_reordering() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));

        for loss_percent in [0usize, 1, 10, 25] {
            let mut sender = SimpleSenderCore::new(0x1122_3344, 512);
            let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Bitmask);
            let packets = (0u32..400)
                .map(|sequence| sender.send_payload(&sequence.to_be_bytes(), ntp, now))
                .collect::<Vec<_>>();
            let mut arrivals = packets
                .iter()
                .filter(|packet| {
                    packet.sequence == 0
                        || packet.sequence == 399
                        || (packet.sequence as usize * 37) % 100 >= loss_percent
                })
                .collect::<Vec<_>>();
            for pair in arrivals.chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
            for packet in arrivals {
                receiver.accept_packet(&packet.bytes).unwrap();
            }

            let missing_before = receiver.missing_sequences();
            if loss_percent == 0 {
                assert!(missing_before.is_empty());
                continue;
            }
            assert!(!missing_before.is_empty());
            let feedback = receiver.build_feedback();
            let retries = sender.handle_feedback(&feedback).unwrap();
            for retry in retries {
                receiver.accept_packet(&retry.bytes).unwrap();
            }
            assert!(
                receiver.missing_sequences().is_empty(),
                "{loss_percent}% loss was not fully repaired"
            );
        }
    }

    #[test]
    fn receiver_resets_sequence_window_when_the_sender_ssrc_restarts() {
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let old = encode_packet(RtpHeader::new_mpegts(40_000, 90_000, 10), b"old");
        // 11 would be SSRC 10's retry bit; a restart picks a new flow id.
        let restarted = encode_packet(RtpHeader::new_mpegts(0, 90_000, 12), b"restarted");

        assert_eq!(receiver.accept_packet(&old).unwrap().sequence, 40_000);
        let received = receiver.accept_packet(&restarted).unwrap();
        assert_eq!(received.sequence, 0);
        assert!(!received.duplicate);
        assert!(received.newly_missing.is_empty());
        assert!(receiver.missing_sequences().is_empty());
    }

    #[test]
    fn receiver_ring_uses_a_ts_payload_floor_and_allocates_lazily() {
        let product = RecoveryConfig::default();
        // 100 Mbit/s for 1 s of 1316-byte payloads is 9498 packets.
        assert_eq!(recovery_window_packets(&product), 9_498);
        let receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range)
            .with_recovery_config(product.clone(), CongestionControlMode::Normal);
        assert_eq!(receiver.missing_tracker.capacity(), 16_384);

        let tiny = RecoveryConfig {
            max_bitrate: 1_000,
            length_min: Duration::from_millis(50),
            length_max: Duration::from_millis(50),
            ..RecoveryConfig::default()
        };
        assert_eq!(recovery_window_packets(&tiny), 1_024);
        let huge = RecoveryConfig {
            max_bitrate: u32::MAX,
            length_min: Duration::from_secs(30),
            length_max: Duration::from_secs(30),
            ..RecoveryConfig::default()
        };
        assert_eq!(recovery_window_packets(&huge), 32_768);
    }

    /// The caller's poll period in the packing tests (above the 15 ms
    /// reorder buffer, so every poll finds the holes due).
    const TICK: Duration = Duration::from_millis(20);

    /// No echo requests, no RTT measurement, no extras: re-NACKs at
    /// 1.1 x rtt_min + 1 ms. For tests about packing, not timing.
    fn static_tuning() -> RecoveryTuning {
        RecoveryTuning {
            measure_rtt: false,
            ..RecoveryTuning::librist_like()
        }
    }

    fn lossy_receiver(recovery: RecoveryConfig, holes: u32) -> (SimpleReceiverCore, Instant) {
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_recovery_config(recovery, CongestionControlMode::Normal)
            .with_recovery_tuning(static_tuning());
        let start = Instant::now();
        for n in 0..=holes {
            let packet =
                encode_packet(RtpHeader::new_mpegts((2 * n) as u16, 0, 0x1122_3344), b"ts");
            receiver.accept_packet_at(&packet, start).unwrap();
        }
        (receiver, start)
    }

    #[test]
    fn many_holes_produce_several_mtu_sized_nack_packets_oldest_first() {
        let (mut receiver, start) = lossy_receiver(RecoveryConfig::default(), 5_000);
        assert_eq!(receiver.missing_sequences().len(), 5_000);
        let now = start + TICK;
        let mut packets = Vec::new();
        assert_eq!(receiver.poll_rtcp_into(now, 0, &mut packets, 64), 25);
        let mut requested = Vec::new();
        for packet in &packets {
            assert!(packet.len() <= 1_200, "{} bytes", packet.len());
            assert!(matches!(
                decode_compound(packet).unwrap()[0],
                RtcpPacket::ReceiverReport(_)
            ));
            requested.extend(decode_nacks_from_compound(packet).unwrap());
        }
        assert_eq!(requested, (0..5_000).map(|n| 2 * n + 1).collect::<Vec<_>>());
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 25);
        assert_eq!(stats.nack_entries_sent, 5_000);
        assert_eq!(stats.nack_entries_deferred, 0);
        assert_eq!(stats.feedback_packets, 25);
        assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, 1);
    }

    #[test]
    fn legacy_poll_rtcp_sends_one_packet_and_keeps_the_rest_due() {
        let (mut receiver, start) = lossy_receiver(RecoveryConfig::default(), 500);
        let first = receiver.poll_rtcp(start + TICK, 0).unwrap();
        let requested = decode_nacks_from_compound(&first).unwrap();
        assert_eq!(requested, (0..200).map(|n| 2 * n + 1).collect::<Vec<_>>());
        assert_eq!(receiver.missing_tracker.hole(401).unwrap().nack_count, 0);
        // The next poll serves the repeat of the oldest holes first, then
        // the holes never requested.
        let mut packets = Vec::new();
        receiver.poll_rtcp_into(start + 2 * TICK, 0, &mut packets, 64);
        let requested = packets
            .iter()
            .flat_map(|packet| decode_nacks_from_compound(packet).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requested.len(), 500);
        assert_eq!(requested[0], 1);
        assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, 2);
        assert_eq!(receiver.missing_tracker.hole(401).unwrap().nack_count, 1);
    }

    #[test]
    fn refused_return_bandwidth_keeps_holes_due_for_the_next_window() {
        let recovery = RecoveryConfig {
            return_max_bitrate: 1,
            length_min: Duration::from_secs(3),
            length_max: Duration::from_secs(3),
            ..RecoveryConfig::default()
        };
        // 1 kbit/s is 125 bytes per second: less than one NACK for 30 holes.
        let (mut receiver, start) = lossy_receiver(recovery, 30);
        let window = receiver.return_window_started;
        let mut packets = Vec::new();
        let now = start + TICK;
        assert_eq!(receiver.poll_rtcp_into(now, 0, &mut packets, 64), 0);
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 0);
        assert_eq!(stats.feedback_packets, 0);
        assert_eq!(stats.nack_entries_deferred, 30);
        let hole = receiver.missing_tracker.hole(1).unwrap();
        assert_eq!(hole.nack_count, 0);
        assert_eq!(hole.next_nack_at, Some(window + Duration::from_secs(1)));

        receiver.recovery.return_max_bitrate = 100_000;
        let later = window + Duration::from_secs(1) + TICK;
        assert_eq!(receiver.poll_rtcp_into(later, 0, &mut packets, 64), 1);
        assert_eq!(
            decode_nacks_from_compound(&packets[0]).unwrap(),
            (0..30).map(|n| 2 * n + 1).collect::<Vec<_>>()
        );
        assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, 1);
        assert_eq!(receiver.stats().nack_entries_sent, 30);
    }

    #[test]
    fn sequences_extend_relative_to_the_highest_not_the_last_packet() {
        let start = Instant::now();
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let packet =
            |sequence: u32| encode_packet(RtpHeader::new_mpegts(sequence as u16, 0, 1), b"ts");
        receiver.accept_packet_at(&packet(8_999), start).unwrap();
        // Lose 9000, then everything up to 40000 arrives.
        for sequence in 9_001..=40_000 {
            receiver.accept_packet_at(&packet(sequence), start).unwrap();
        }
        // The repair of 9000 (31000 behind) arrives, then a packet after a
        // further burst: 33000 ahead of the repair but near the highest.
        let repair = receiver.accept_packet_at(&packet(9_000), start).unwrap();
        assert!(repair.recovered);
        assert_eq!(repair.sequence, 9_000);
        let next = receiver.accept_packet_at(&packet(42_000), start).unwrap();
        assert_eq!(next.sequence, 42_000);
        assert!(!next.duplicate);
        assert_eq!(next.newly_missing.len(), 1_999);
    }

    #[test]
    fn outage_longer_than_horizon_resyncs_without_dropping() {
        let start = Instant::now();
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let packet =
            |sequence: u32| encode_packet(RtpHeader::new_mpegts(sequence as u16, 0, 1), b"ts");
        for sequence in 0..=1_000 {
            receiver.accept_packet_at(&packet(sequence), start).unwrap();
        }
        // An outage of 40000 packets: the low 16 bits of the next packet lie
        // 25535 "behind" the highest, beyond the duplicate ring, with no hole.
        assert!(receiver.missing_tracker.capacity() < 25_535);
        for sequence in 41_001..=41_100 {
            let received = receiver.accept_packet_at(&packet(sequence), start).unwrap();
            assert!(!received.duplicate, "{sequence} refused as a duplicate");
            assert!(!received.recovered);
            assert_eq!(received.sequence, sequence);
        }
        assert_eq!(receiver.highest_sequence, Some(41_100));
        // Of the 40000 lost, those within the horizon of 41100 stay tracked.
        let oldest = 41_100 - MAX_TRACKED_HOLE_DISTANCE;
        let missing = receiver.missing_sequences();
        assert_eq!(missing.first(), Some(&oldest));
        assert_eq!(missing.last(), Some(&41_000));
        let stats = receiver.stats();
        assert_eq!(stats.duplicate_packets, 0);
        assert_eq!(stats.holes_unaddressable, u64::from(oldest - 1_001));
    }

    #[test]
    fn packets_behind_within_the_ring_or_on_a_hole_still_extend_backward() {
        let start = Instant::now();
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let packet =
            |sequence: u32| encode_packet(RtpHeader::new_mpegts(sequence as u16, 0, 1), b"ts");
        receiver.accept_packet_at(&packet(65_530), start).unwrap();
        // Forward across the 16-bit wrap, leaving 65531..=65535 missing.
        let wrapped = receiver.accept_packet_at(&packet(65_536), start).unwrap();
        assert_eq!(wrapped.sequence, 65_536);
        assert_eq!(wrapped.newly_missing.len(), 5);
        // A duplicate inside the ring stays a duplicate.
        let duplicate = receiver.accept_packet_at(&packet(65_530), start).unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.sequence, 65_530);
        // A repair of an open hole stays a repair.
        let repair = receiver.accept_packet_at(&packet(65_533), start).unwrap();
        assert!(repair.recovered);
        assert_eq!(repair.sequence, 65_533);
    }

    #[test]
    fn zero_repeat_sends_one_nack_per_poll() {
        let recovery = RecoveryConfig {
            rtt_min: Duration::ZERO,
            rtt_max: Duration::ZERO,
            reorder_buffer: Duration::ZERO,
            length_min: Duration::from_secs(5),
            length_max: Duration::from_secs(5),
            ..RecoveryConfig::default()
        };
        let (mut receiver, start) = lossy_receiver(recovery, 1);
        assert_eq!(receiver.missing_sequences(), vec![1]);
        for tick in 1..=3_u32 {
            let now = start + TICK * tick;
            let mut packets = Vec::new();
            assert_eq!(receiver.poll_rtcp_into(now, 0, &mut packets, 64), 1);
            assert_eq!(decode_nacks_from_compound(&packets[0]).unwrap(), vec![1]);
            assert_eq!(receiver.missing_tracker.hole(1).unwrap().nack_count, tick);
        }
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 3);
        assert_eq!(stats.nack_entries_sent, 3);
        assert_eq!(stats.nack_entries_deferred, 0);
    }

    fn contiguous_loss_receiver(lost: u16) -> (SimpleReceiverCore, Instant) {
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range)
            .with_recovery_tuning(static_tuning());
        let start = Instant::now();
        for sequence in [0, lost + 1] {
            let packet = encode_packet(RtpHeader::new_mpegts(sequence, 0, 1), b"ts");
            receiver.accept_packet_at(&packet, start).unwrap();
        }
        assert_eq!(receiver.poll_rtcp_into(start, 0, &mut Vec::new(), 1), 0);
        (receiver, start)
    }

    #[test]
    fn one_packet_poll_carries_a_whole_contiguous_burst_in_ranges() {
        let (mut receiver, start) = contiguous_loss_receiver(1_000);
        let packet = receiver.poll_rtcp(start + TICK, 0).unwrap();
        assert_eq!(
            decode_nacks_from_compound(&packet).unwrap(),
            (1..=1_000).collect::<Vec<_>>()
        );
        let stats = receiver.stats();
        assert_eq!(stats.nack_entries_sent, 1_000);
        assert_eq!(stats.nack_entries_deferred, 0);
        assert_eq!(receiver.missing_tracker.hole(1_000).unwrap().nack_count, 1);
    }

    #[test]
    fn one_packet_poll_stops_at_the_per_packet_sequence_cap() {
        let (mut receiver, start) = contiguous_loss_receiver(5_000);
        let packet = receiver.poll_rtcp(start + TICK, 0).unwrap();
        let requested = decode_nacks_from_compound(&packet).unwrap();
        assert_eq!(requested.len(), MAX_NACK_PACKET_REQUESTS);
        assert_eq!(requested[0], 1);
        let stats = receiver.stats();
        assert_eq!(stats.nack_entries_sent, MAX_NACK_PACKET_REQUESTS as u64);
        assert_eq!(stats.nack_entries_deferred, 0);
        assert_eq!(receiver.missing_tracker.hole(4_096).unwrap().nack_count, 1);
        assert_eq!(receiver.missing_tracker.hole(4_097).unwrap().nack_count, 0);
    }

    #[test]
    fn a_refused_send_commits_only_the_packets_that_went_out() {
        let (mut receiver, start) = lossy_receiver(RecoveryConfig::default(), 1_000);
        let now = start + TICK;
        let mut calls = 0;
        let mut accepted = Vec::new();
        let produced = receiver.poll_rtcp_with(now, 0, 64, |packet| {
            calls += 1;
            if calls <= 2 {
                accepted.push(packet.to_vec());
                true
            } else {
                false
            }
        });
        assert_eq!(produced, 2);
        // Nothing is offered after the refusal, not even a report.
        assert_eq!(calls, 3);
        let sent = accepted
            .iter()
            .flat_map(|packet| decode_nacks_from_compound(packet).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(sent, (0..400).map(|n| 2 * n + 1).collect::<Vec<_>>());
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 2);
        assert_eq!(stats.feedback_packets, 2);
        assert_eq!(stats.nack_entries_sent, 400);
        assert_eq!(stats.nack_entries_deferred, 600);
        let bytes = accepted.iter().map(Vec::len).sum::<usize>() as u64;
        assert_eq!(receiver.return_window_bytes, bytes);
        assert_eq!(receiver.missing_tracker.hole(799).unwrap().nack_count, 1);
        let refused = receiver.missing_tracker.hole(801).unwrap();
        assert_eq!(refused.nack_count, 0);
        assert_eq!(refused.last_nack_at, None);
        assert_eq!(refused.next_nack_at, Some(now));

        // The next poll requests the refused holes (and repeats the sent ones).
        let mut packets = Vec::new();
        receiver.poll_rtcp_into(now + TICK, 0, &mut packets, 64);
        let requested = packets
            .iter()
            .flat_map(|packet| decode_nacks_from_compound(packet).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requested.len(), 1_000);
        assert_eq!(receiver.missing_tracker.hole(801).unwrap().nack_count, 1);
    }

    #[test]
    fn a_refused_report_is_not_counted() {
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        let start = Instant::now();
        assert_eq!(receiver.poll_rtcp_into(start, 0, &mut Vec::new(), 1), 0);
        let mut calls = 0;
        let report_due = start + DEFAULT_RTCP_REPORT_INTERVAL;
        let produced = receiver.poll_rtcp_with(report_due, 0, 1, |_| {
            calls += 1;
            false
        });
        assert_eq!((produced, calls), (0, 1));
        assert_eq!(receiver.stats().feedback_packets, 0);
    }

    #[test]
    fn receiver_report_counts_expected_packets_across_the_u32_rollover() {
        let start = Instant::now();
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
        receiver.highest_sequence = Some(u32::MAX - 1);
        receiver.base_sequence = Some(u32::MAX - 1);
        receiver.sequence_extender.extend(u16::MAX - 1);
        receiver.missing_tracker.observe_at(u32::MAX - 1, start);
        receiver.stats.received_packets = 1;
        let packet = encode_packet(RtpHeader::new_mpegts(2, 0, 1), b"ts");
        assert_eq!(
            receiver.accept_packet_at(&packet, start).unwrap().sequence,
            2
        );
        let report = receiver.receiver_report(0);
        assert_eq!(report.highest_sequence, 2);
        // Expected u32::MAX-1 ..= 2 (5 packets), received 2.
        assert_eq!(report.cumulative_packet_loss, 3);
    }

    fn echo_request_compound(ssrc: u32, ntp_timestamp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_empty_receiver_report(ssrc, &mut out);
        encode_echo(
            Echo {
                ssrc,
                ntp_timestamp,
                kind: EchoKind::Request,
            },
            &mut out,
        );
        out
    }

    #[test]
    fn sender_answers_echo_request() {
        let request_ntp = ntp_from_unix_duration(Duration::from_secs(5));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64).with_cname("tx");
        let outcome = sender
            .handle_feedback_outcome_at(
                &echo_request_compound(0x5566_7788, request_ntp),
                request_ntp,
                Instant::now(),
            )
            .unwrap();
        assert!(outcome.retries.is_empty());
        assert_eq!(outcome.responses.len(), 1);
        let decoded = decode_compound(&outcome.responses[0]).unwrap();
        assert_eq!(
            decoded.last(),
            Some(&RtcpPacket::Echo(Echo {
                ssrc: 0x5566_7788,
                ntp_timestamp: request_ntp,
                kind: EchoKind::Response { delay: 0 },
            }))
        );
        // librist's layout: empty RR and SDES of the sender's flow first, so
        // a Main receiver routes the response to that flow.
        assert_eq!(&outcome.responses[0][4..8], &0x1122_3344u32.to_be_bytes());
        assert!(decoded.contains(&RtcpPacket::SourceDescription {
            ssrc: 0x1122_3344,
            cname: "tx".to_string(),
        }));
        assert_eq!(sender.stats().echo_responses, 1);
        // The legacy entry point still retransmits but does not answer.
        let retries = sender
            .handle_feedback_at(&echo_request_compound(1, request_ntp), request_ntp)
            .unwrap();
        assert!(retries.is_empty());
        assert_eq!(sender.stats().echo_responses, 2);
    }

    #[test]
    fn receiver_answer_to_sender_echo_feeds_a_smoothed_rtt() {
        let base = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        for (sent_ms, rtt_ms) in [(0u64, 8u64), (100, 16)] {
            let sent = base + (sent_ms << 32) / 1000;
            let request = sender.build_echo_request(sent);
            let response = receiver.handle_rtcp_at(&request, sent).unwrap().remove(0);
            let back = sent + (rtt_ms << 32) / 1000;
            sender
                .handle_feedback_outcome_at(&response, back, Instant::now())
                .unwrap();
        }
        // 8 ms seeds the estimate; 16 ms moves it by one eighth.
        assert_eq!(sender.stats().rtt_micros, Some(9_000));
    }

    #[test]
    fn retry_sets_ssrc_lsb_and_keeps_every_other_byte() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let original = sender.send_payload(b"lost", ntp, now);
        let retries = sender.retransmit_at(&[original.sequence], now);
        assert_eq!(retries.len(), 1);
        let retry = &retries[0].bytes;
        assert_eq!(RtpPacket::decode(retry).unwrap().header.ssrc, 0x1122_3345);
        let mut unmarked = retry.clone();
        unmarked[11] &= !1;
        assert_eq!(unmarked, original.bytes);
    }

    #[test]
    fn simple_receiver_accepts_retry_marked_ssrc() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let packets = (0..6)
            .map(|index| sender.send_payload(&[index], ntp, now))
            .collect::<Vec<_>>();
        receiver.accept_packet(&packets[0].bytes).unwrap();
        receiver.accept_packet(&packets[3].bytes).unwrap();
        receiver.accept_packet(&packets[5].bytes).unwrap();
        assert_eq!(receiver.missing_sequences(), vec![1, 2, 4]);

        // A librist (or rist-rs) retransmission carries SSRC | 1.
        let retry = sender.retransmit_at(&[2], now);
        let recovered = receiver.accept_packet(&retry[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert!(!recovered.duplicate);
        assert_eq!(recovered.payload, vec![2]);
        // The other holes survive: the retry bit is not a new sender.
        assert_eq!(receiver.missing_sequences(), vec![1, 4]);
        assert_eq!(receiver.stats().retry_packets_received, 1);
        assert_eq!(receiver.stats().holes_reset, 0);
        // The receiver report names the flow, not the retry SSRC.
        let report = receiver.build_receiver_report(ntp);
        assert_eq!(&report[8..12], &0x1122_3344u32.to_be_bytes());
    }

    fn ts_packet(pid: u16, label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xff; TS_PACKET_SIZE];
        packet[0] = TS_SYNC_BYTE;
        packet[1..3].copy_from_slice(&pid.to_be_bytes());
        packet[3] = 0x10;
        packet[4..4 + label.len()].copy_from_slice(label);
        packet
    }
}
