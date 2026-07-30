use crate::mpegts::{expand_null_packets, suppress_null_packets};
use crate::packet::rtcp::{
    decode_compound, decode_nacks_from_compound, encode_echo, encode_empty_receiver_report,
    encode_nack, encode_receiver_report, encode_sdes_cname, encode_sender_report, Echo, EchoKind,
    NackMode, ReceiverReport, RtcpPacket, SenderReport,
};
use crate::packet::rtp::{
    encode_packet, encode_packet_with_extension, RistRtpExtension, RtpHeader, RtpPacket,
    RTP_PAYLOAD_TYPE_MPEGTS,
};
use crate::recovery::SenderHistory;
use crate::sequence::extend_near;
use crate::stats::{ReceiverStats, SenderStats};
use crate::time::{calculate_rtt_micros, mpegts_rtp_timestamp, ntp_now};
use crate::{
    CongestionControlMode, MissingTracker, RecoveryConfig, RecoveryMode, Result, SequenceExtender,
};
use std::time::{Duration, Instant};

pub const DEFAULT_RTCP_FEEDBACK_INTERVAL: Duration = Duration::from_millis(20);
pub const DEFAULT_RTCP_REPORT_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_RTCP_ECHO_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    pub sequence: u32,
    pub retry: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SimpleSenderPeerState {
    retry_slots: Vec<SenderPeerRetrySlot>,
    retry_mask: usize,
    retry_window_started: Instant,
    retry_window_bytes: u64,
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
            stats: SenderStats::new(flow_id),
        }
    }

    pub fn stats(&self) -> SenderStats {
        self.stats
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
    ) -> bool {
        let Some(slot) = self
            .retry_slots
            .get_mut(sequence as usize & self.retry_mask)
        else {
            return false;
        };
        if slot.sequence != sequence {
            *slot = SenderPeerRetrySlot {
                sequence,
                retry_count: 0,
                last_retry_at: None,
            };
        }
        if slot.retry_count >= maximum_retries
            || slot
                .last_retry_at
                .is_some_and(|last| now.saturating_duration_since(last) < minimum_spacing)
        {
            return false;
        }
        slot.retry_count += 1;
        slot.last_retry_at = Some(now);
        true
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

    pub fn handle_feedback(&mut self, packet: &[u8]) -> Result<Vec<OutboundPacket>> {
        self.handle_feedback_at(packet, ntp_now())
    }

    pub fn handle_feedback_at(
        &mut self,
        packet: &[u8],
        now_ntp: u64,
    ) -> Result<Vec<OutboundPacket>> {
        self.recovery_state.stats.record_feedback();
        update_sender_rtcp_state(packet, now_ntp, &mut self.recovery_state.stats)?;
        let reference = self.next_sequence.wrapping_sub(1);
        let sequences = decode_nacks_from_compound(packet)?
            .into_iter()
            .map(|sequence| extend_near(reference, sequence as u16))
            .collect::<Vec<_>>();
        Ok(self.retransmit(&sequences))
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
        state.stats.record_feedback();
        update_sender_rtcp_state(packet, now_ntp, &mut state.stats)?;
        let reference = self.next_sequence.wrapping_sub(1);
        let sequences = decode_nacks_from_compound(packet)?
            .into_iter()
            .map(|sequence| extend_near(reference, sequence as u16))
            .collect::<Vec<_>>();
        Ok(self.retransmit_for_peer_at(state, &sequences, now))
    }

    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    pub fn set_next_sequence(&mut self, sequence: u32) {
        self.next_sequence = sequence;
    }

    pub fn stats(&self) -> SenderStats {
        let mut stats = self.stats;
        stats.retransmitted_packets = self.recovery_state.stats.retransmitted_packets;
        stats.retransmitted_bytes = self.recovery_state.stats.retransmitted_bytes;
        stats.feedback_packets = self.recovery_state.stats.feedback_packets;
        stats.rtt_micros = self.recovery_state.stats.rtt_micros;
        stats
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
    if recovery.mode == RecoveryMode::Disabled {
        return Vec::new();
    }
    if now.saturating_duration_since(state.retry_window_started) >= Duration::from_secs(1) {
        state.retry_window_started = now;
        state.retry_window_bytes = 0;
    }
    let rtt = Duration::from_micros(
        state
            .stats
            .rtt_micros
            .unwrap_or(recovery.rtt_min.as_micros() as u64),
    )
    .clamp(recovery.rtt_min, recovery.rtt_max);
    let spacing = match congestion_control {
        CongestionControlMode::Off => Duration::ZERO,
        CongestionControlMode::Normal => rtt,
        CongestionControlMode::Aggressive => rtt.saturating_mul(2),
    };
    let maximum_bytes = u64::from(recovery.max_bitrate)
        .saturating_mul(1_000)
        .saturating_div(8);
    let mut packets = Vec::new();
    for &sequence in sequences {
        let Some(packet) = history.get(sequence) else {
            continue;
        };
        if now.saturating_duration_since(packet.inserted_at) > effective_recovery_age(recovery)
            || (maximum_bytes > 0
                && state
                    .retry_window_bytes
                    .saturating_add(packet.payload_len as u64)
                    > maximum_bytes)
            || !state.take_retry(sequence, now, spacing, recovery.max_retries)
        {
            continue;
        }
        state.retry_window_bytes = state
            .retry_window_bytes
            .saturating_add(packet.payload_len as u64);
        state.stats.record_retransmit(packet.payload_len);
        packets.push(OutboundPacket {
            sequence: packet.sequence,
            retry: true,
            bytes: packet.payload.clone(),
        });
    }
    packets
}

fn update_sender_rtcp_state(packet: &[u8], now_ntp: u64, stats: &mut SenderStats) -> Result<()> {
    for packet in decode_compound(packet)? {
        if let RtcpPacket::Echo(Echo {
            ntp_timestamp,
            kind: EchoKind::Response { delay },
            ..
        }) = packet
        {
            stats.set_rtt_micros(calculate_rtt_micros(ntp_timestamp, now_ntp, delay));
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
}

impl SimpleReceiverCore {
    pub fn new(flow_id: u32, cname: impl Into<String>, nack_mode: NackMode) -> Self {
        Self {
            flow_id,
            cname: cname.into(),
            nack_mode,
            sequence_extender: SequenceExtender::new(),
            missing_tracker: MissingTracker::new(),
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
        let window = recovery_window_packets(&recovery);
        self.missing_tracker =
            MissingTracker::with_limits(window, effective_recovery_age(&recovery));
        self.recovery = recovery;
        self.congestion_control = congestion_control;
        self.return_window_started = Instant::now();
        self.return_window_bytes = 0;
    }

    pub fn accept_packet(&mut self, packet: &[u8]) -> Result<ReceivedPayload> {
        let packet = RtpPacket::decode(packet)?;
        self.accept_rtp_packet(packet)
    }

    pub fn accept_rtp_packet(&mut self, packet: RtpPacket<'_>) -> Result<ReceivedPayload> {
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
        let sequence = self.sequence_extender.extend(packet.header.sequence_number);
        self.peer_ssrc = Some(packet.header.ssrc);
        if self.base_sequence.is_none() {
            self.base_sequence = Some(sequence);
        }
        self.highest_sequence = Some(
            self.highest_sequence
                .map_or(sequence, |highest| highest.max(sequence)),
        );
        let observation = self.missing_tracker.observe(sequence);
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
        let currently_missing = self.missing_tracker.missing_sequences().count();
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

    pub fn poll_rtcp(&mut self, now: Instant, now_ntp: u64) -> Option<Vec<u8>> {
        let due = self.rtcp.poll_receiver(now);
        let repeat_delay = match self.congestion_control {
            CongestionControlMode::Off => Duration::ZERO,
            CongestionControlMode::Normal => self.recovery.rtt_min,
            CongestionControlMode::Aggressive => self.recovery.rtt_min.saturating_mul(2),
        };

        if due.feedback {
            let missing = self.missing_tracker.nacks_due(
                now,
                self.recovery.reorder_buffer,
                repeat_delay.clamp(self.recovery.rtt_min, self.recovery.rtt_max),
                self.recovery.min_retries,
                self.recovery.max_retries,
            );
            if !missing.is_empty() {
                self.stats.record_feedback();
                let mut out = self.build_receiver_report(now_ntp);
                encode_nack(self.nack_mode, self.flow_id, &missing, &mut out);
                if self.allow_return_bytes(now, out.len()) {
                    return Some(out);
                }
            }
        }

        if due.report {
            self.stats.record_feedback();
            return Some(self.build_receiver_report(now_ntp));
        }

        None
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
        self.stats
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
        let expected_packets = highest_sequence
            .checked_sub(base_sequence)
            .map(|expected| u64::from(expected) + 1)
            .unwrap_or(0);
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

fn recovery_window_packets(config: &RecoveryConfig) -> usize {
    // max_bitrate is expressed in kbit/s. Use a conservative 64-byte packet
    // floor so even very small datagrams cannot make the sequence window grow
    // beyond this fixed allocation.
    let bits = u128::from(config.max_bitrate)
        .saturating_mul(1_000)
        .saturating_mul(effective_recovery_age(config).as_millis());
    let packets = bits
        .saturating_div(8)
        .saturating_div(64)
        .saturating_div(1_000)
        .clamp(64, 1 << 20);
    usize::try_from(packets).unwrap_or(1 << 20)
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
        let mut expired =
            SimpleSenderCore::new(1, 8).with_recovery_config(recovery, CongestionControlMode::Off);
        let old = expired.send_payload(b"old", ntp, start);
        assert!(expired
            .retransmit_at(&[old.sequence], start + Duration::from_millis(101))
            .is_empty());
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
        let restarted = encode_packet(RtpHeader::new_mpegts(0, 90_000, 11), b"restarted");

        assert_eq!(receiver.accept_packet(&old).unwrap().sequence, 40_000);
        let received = receiver.accept_packet(&restarted).unwrap();
        assert_eq!(received.sequence, 0);
        assert!(!received.duplicate);
        assert!(received.newly_missing.is_empty());
        assert!(receiver.missing_sequences().is_empty());
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
