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
use crate::recovery::{NackSchedule, SenderHistory, MAX_TRACKED_HOLE_DISTANCE};
use crate::rtt::RttEstimator;
use crate::sequence::extend_near;
use crate::stats::{ReceiverStats, SenderStats};
use crate::time::{calculate_rtt_micros, mpegts_rtp_timestamp, ntp_now};
use crate::{
    CongestionControlMode, MissingTracker, RecoveryConfig, RecoveryMode, Result, SequenceExtender,
};
use std::time::{Duration, Instant};

pub const DEFAULT_RTCP_FEEDBACK_INTERVAL: Duration = Duration::from_millis(20);
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
    next_feedback: Option<Instant>,
    next_report: Option<Instant>,
    next_echo: Option<Instant>,
}

impl RtcpScheduler {
    fn new(intervals: RtcpIntervals) -> Self {
        Self {
            intervals,
            next_feedback: None,
            next_report: None,
            next_echo: None,
        }
    }

    fn poll_sender(&mut self, now: Instant) -> RtcpDue {
        RtcpDue {
            report: poll_due(&mut self.next_report, now, self.intervals.report),
            echo: poll_due(&mut self.next_echo, now, self.intervals.echo),
            feedback: false,
        }
    }

    fn poll_receiver(&mut self, now: Instant) -> RtcpDue {
        RtcpDue {
            feedback: poll_due(&mut self.next_feedback, now, self.intervals.feedback),
            report: poll_due(&mut self.next_report, now, self.intervals.report),
            echo: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RtcpDue {
    feedback: bool,
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
            recovery_state: SimpleSenderPeerState::new(ssrc, history_packets),
        }
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
        retransmit_from_history(
            &self.history,
            &self.recovery,
            self.congestion_control,
            sequences,
            now,
            &mut self.recovery_state,
        )
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
        retransmit_from_history(
            &self.history,
            &self.recovery,
            self.congestion_control,
            sequences,
            now,
            state,
        )
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
        let context = SenderContext {
            ssrc: self.ssrc,
            cname: &self.cname,
            reference: self.next_sequence.wrapping_sub(1),
            history: &self.history,
            recovery: &self.recovery,
            congestion_control: self.congestion_control,
        };
        context.handle_feedback(&mut self.recovery_state, packet, now_ntp, now)
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
    history: &SenderHistory,
    recovery: &RecoveryConfig,
    congestion_control: CongestionControlMode,
    sequences: &[u32],
    now: Instant,
    state: &mut SimpleSenderPeerState,
) -> Vec<OutboundPacket> {
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
    let maximum_age = effective_recovery_age(recovery);
    for &sequence in sequences {
        let Some(packet) = history.get(sequence) else {
            state.stats.retransmit_refused_not_in_history += 1;
            continue;
        };
        if now.saturating_duration_since(packet.inserted_at) > maximum_age {
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
        let retries = retransmit_from_history(
            self.history,
            self.recovery,
            self.congestion_control,
            &sequences,
            now,
            state,
        );
        Ok(FeedbackOutcome { retries, responses })
    }
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
            RtcpPacket::Echo(request @ Echo {
                kind: EchoKind::Request,
                ..
            }) => echo_requests.push(request),
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
        }
    }

    pub fn with_rtcp_intervals(mut self, intervals: RtcpIntervals) -> Self {
        self.rtcp = RtcpScheduler::new(intervals);
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
        let due = self.rtcp.poll_receiver(now);
        let mut produced = 0;
        if due.feedback
            && self
                .missing_tracker
                .next_nack_at()
                .is_some_and(|at| at <= now)
        {
            produced = self.push_due_nacks(now, now_ntp, max_packets, &mut send);
        }
        if due.report && produced == 0 {
            let report = self.build_receiver_report(now_ntp);
            if send(&report) {
                self.stats.record_feedback();
                produced = 1;
            }
        }
        produced
    }

    fn nack_repeat_delay(&self) -> Duration {
        let rtt_min = self.recovery.rtt_min;
        let repeat = match self.congestion_control {
            CongestionControlMode::Off => Duration::ZERO,
            CongestionControlMode::Normal => rtt_min,
            CongestionControlMode::Aggressive => rtt_min.saturating_mul(2),
        };
        repeat.max(rtt_min).min(self.recovery.rtt_max.max(rtt_min))
    }

    /// Takes the due holes once, sized by what `max_packets` packets can
    /// carry, and encodes them into packets oldest first. Holes committed
    /// here are never taken again in the same poll, even with a zero repeat
    /// delay; holes that do not fit stay due from `now`.
    fn push_due_nacks(
        &mut self,
        now: Instant,
        now_ntp: u64,
        max_packets: usize,
        send: &mut dyn FnMut(&[u8]) -> bool,
    ) -> usize {
        let repeat = self.nack_repeat_delay();
        let schedule = NackSchedule {
            initial_delay: self.recovery.reorder_buffer,
            repeat_delay: repeat,
            max_retries: self.recovery.max_retries,
            min_time_left: Duration::ZERO,
        };
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
                    .commit_nacks(&due[sent..sent + count], now, repeat);
                self.stats.record_nack_packet(count);
                produced += 1;
                sent += count;
            }
            self.nack_packet_scratch = packet;
        }
        if sent < due.len() {
            self.missing_tracker.defer_nacks(&due[sent..], retry_at);
            self.stats.nack_entries_deferred += (due.len() - sent) as u64;
        }
        due.clear();
        self.nack_scratch = due;
        produced
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

    #[test]
    fn receiver_polls_scheduled_feedback_when_missing() {
        let start = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let intervals = RtcpIntervals {
            feedback: Duration::from_millis(10),
            report: Duration::from_secs(1),
            echo: Duration::from_secs(1),
        };
        let mut sender = SimpleSenderCore::new(0x1122_3344, 64);
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rtcp_intervals(intervals);

        assert_eq!(receiver.poll_rtcp(start, ntp), None);
        let first = sender.send_payload(b"first", ntp, start);
        let _lost = sender.send_payload(b"lost", ntp, start);
        let third = sender.send_payload(b"third", ntp, start);
        receiver.accept_packet(&first.bytes).unwrap();
        receiver.accept_packet(&third.bytes).unwrap();

        assert_eq!(
            receiver.poll_rtcp(start + Duration::from_millis(10), ntp),
            None
        );
        let packet = receiver
            .poll_rtcp(start + Duration::from_millis(20), ntp)
            .unwrap();
        assert_eq!(decode_nacks_from_compound(&packet).unwrap(), vec![1]);
        assert_eq!(receiver.stats().feedback_packets, 1);
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
        assert!(expired
            .retransmit_at(&[old.sequence], start + Duration::from_millis(101))
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

    fn lossy_receiver(recovery: RecoveryConfig, holes: u32) -> (SimpleReceiverCore, Instant) {
        let mut receiver = SimpleReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_recovery_config(recovery, CongestionControlMode::Normal);
        for n in 0..=holes {
            let packet =
                encode_packet(RtpHeader::new_mpegts((2 * n) as u16, 0, 0x1122_3344), b"ts");
            receiver.accept_packet(&packet).unwrap();
        }
        let start = Instant::now();
        // The first poll only arms the RTCP schedule.
        assert_eq!(receiver.poll_rtcp_into(start, 0, &mut Vec::new(), 64), 0);
        (receiver, start)
    }

    #[test]
    fn many_holes_produce_several_mtu_sized_nack_packets_oldest_first() {
        let (mut receiver, start) = lossy_receiver(RecoveryConfig::default(), 5_000);
        assert_eq!(receiver.missing_sequences().len(), 5_000);
        let now = start + DEFAULT_RTCP_FEEDBACK_INTERVAL;
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
        let first = receiver
            .poll_rtcp(start + DEFAULT_RTCP_FEEDBACK_INTERVAL, 0)
            .unwrap();
        let requested = decode_nacks_from_compound(&first).unwrap();
        assert_eq!(requested, (0..200).map(|n| 2 * n + 1).collect::<Vec<_>>());
        assert_eq!(receiver.missing_tracker.hole(401).unwrap().nack_count, 0);
        // The next poll serves the repeat of the oldest holes first, then
        // the holes never requested.
        let mut packets = Vec::new();
        receiver.poll_rtcp_into(
            start + 2 * DEFAULT_RTCP_FEEDBACK_INTERVAL,
            0,
            &mut packets,
            64,
        );
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
        let now = start + DEFAULT_RTCP_FEEDBACK_INTERVAL;
        assert_eq!(receiver.poll_rtcp_into(now, 0, &mut packets, 64), 0);
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 0);
        assert_eq!(stats.feedback_packets, 0);
        assert_eq!(stats.nack_entries_deferred, 30);
        let hole = receiver.missing_tracker.hole(1).unwrap();
        assert_eq!(hole.nack_count, 0);
        assert_eq!(hole.next_nack_at, Some(window + Duration::from_secs(1)));

        receiver.recovery.return_max_bitrate = 100_000;
        let later = window + Duration::from_secs(1) + DEFAULT_RTCP_FEEDBACK_INTERVAL;
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
            let now = start + DEFAULT_RTCP_FEEDBACK_INTERVAL * tick;
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
        let mut receiver = SimpleReceiverCore::new(1, "rust", NackMode::Range);
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
        let packet = receiver
            .poll_rtcp(start + DEFAULT_RTCP_FEEDBACK_INTERVAL, 0)
            .unwrap();
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
        let packet = receiver
            .poll_rtcp(start + DEFAULT_RTCP_FEEDBACK_INTERVAL, 0)
            .unwrap();
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
        let now = start + DEFAULT_RTCP_FEEDBACK_INTERVAL;
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
        receiver.poll_rtcp_into(now + DEFAULT_RTCP_FEEDBACK_INTERVAL, 0, &mut packets, 64);
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
