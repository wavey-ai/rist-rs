use crate::mpegts::{expand_null_packets, suppress_null_packets};
use crate::packet::rtcp::{
    decode_compound, decode_nacks_from_compound, encode_echo, encode_empty_receiver_report,
    encode_nack, encode_receiver_report, encode_sdes_cname, encode_sender_report, Echo, EchoKind,
    NackMode, ReceiverReport, RtcpPacket, SenderReport,
};
use crate::packet::rtp::{
    encode_packet, encode_packet_with_extension, RistRtpExtension, RtpHeader, RtpPacket,
};
use crate::recovery::SenderHistory;
use crate::stats::{ReceiverStats, SenderStats};
use crate::time::{calculate_rtt_micros, mpegts_rtp_timestamp, ntp_now};
use crate::{MissingTracker, Result, SequenceExtender};
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
        let packets = self
            .history
            .resolve_nacks(sequences.iter().copied())
            .into_iter()
            .map(|packet| OutboundPacket {
                sequence: packet.sequence,
                retry: true,
                bytes: packet.payload.clone(),
            })
            .collect::<Vec<_>>();
        for packet in &packets {
            self.stats.record_retransmit(packet.bytes.len());
        }
        packets
    }

    pub fn handle_feedback(&mut self, packet: &[u8]) -> Result<Vec<OutboundPacket>> {
        self.handle_feedback_at(packet, ntp_now())
    }

    pub fn handle_feedback_at(
        &mut self,
        packet: &[u8],
        now_ntp: u64,
    ) -> Result<Vec<OutboundPacket>> {
        self.stats.record_feedback();
        self.update_rtcp_state(packet, now_ntp)?;
        let sequences = decode_nacks_from_compound(packet)?;
        Ok(self.retransmit(&sequences))
    }

    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    pub fn stats(&self) -> SenderStats {
        self.stats
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

    fn update_rtcp_state(&mut self, packet: &[u8], now_ntp: u64) -> Result<()> {
        for packet in decode_compound(packet)? {
            if let RtcpPacket::Echo(Echo {
                ntp_timestamp,
                kind: EchoKind::Response { delay },
                ..
            }) = packet
            {
                self.stats
                    .set_rtt_micros(calculate_rtt_micros(ntp_timestamp, now_ntp, delay));
            }
        }
        Ok(())
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
        }
    }

    pub fn with_rtcp_intervals(mut self, intervals: RtcpIntervals) -> Self {
        self.rtcp = RtcpScheduler::new(intervals);
        self
    }

    pub fn accept_packet(&mut self, packet: &[u8]) -> Result<ReceivedPayload> {
        let packet = RtpPacket::decode(packet)?;
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
                expand_null_packets(packet.payload, extension.npd_bits)?
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
        let has_missing = self.missing_tracker.missing_sequences().next().is_some();

        if due.feedback && has_missing {
            self.stats.record_feedback();
            return Some(self.build_feedback_at(now_ntp));
        }

        if due.report {
            self.stats.record_feedback();
            return Some(self.build_receiver_report(now_ntp));
        }

        None
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
        let fraction_lost = if expected_packets == 0 {
            0
        } else {
            ((cumulative_loss.saturating_mul(256) / expected_packets).min(255)) as u8
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use crate::packet::rtp::RIST_RTP_EXTENSION_NPD_FLAG;
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

        let packet = receiver
            .poll_rtcp(start + Duration::from_millis(10), ntp)
            .unwrap();
        assert_eq!(decode_nacks_from_compound(&packet).unwrap(), vec![1]);
        assert_eq!(receiver.stats().feedback_packets, 1);
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
