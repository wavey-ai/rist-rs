#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SenderStats {
    pub flow_id: u32,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub retransmitted_packets: u64,
    pub retransmitted_bytes: u64,
    pub feedback_packets: u64,
    pub rtt_micros: Option<u64>,
    /// Sequences requested by received NACKs (before any refusal).
    pub nack_requests: u64,
    /// Requested sequences no longer (or never) in the send history.
    pub retransmit_refused_not_in_history: u64,
    /// Requested sequences older than the recovery buffer.
    pub retransmit_refused_too_old: u64,
    /// Retransmissions refused by the max_bitrate cap.
    pub retransmit_refused_bitrate: u64,
    /// Retransmissions refused because the previous one was less than an RTT ago.
    pub retransmit_refused_spacing: u64,
    /// Retransmissions refused because the sequence reached max_retries.
    pub retransmit_refused_max_retries: u64,
    /// Feedback packets that failed to decode.
    pub feedback_decode_errors: u64,
    /// Echo requests answered.
    pub echo_responses: u64,
    /// Second copies of late repairs sent (also in retransmitted_packets).
    pub duplicate_repairs: u64,
    /// Tail-loss probes sent (also in retransmitted_packets).
    pub tail_probes: u64,
}

impl SenderStats {
    pub fn new(flow_id: u32) -> Self {
        Self {
            flow_id,
            sent_packets: 0,
            sent_bytes: 0,
            retransmitted_packets: 0,
            retransmitted_bytes: 0,
            feedback_packets: 0,
            rtt_micros: None,
            nack_requests: 0,
            retransmit_refused_not_in_history: 0,
            retransmit_refused_too_old: 0,
            retransmit_refused_bitrate: 0,
            retransmit_refused_spacing: 0,
            retransmit_refused_max_retries: 0,
            feedback_decode_errors: 0,
            echo_responses: 0,
            duplicate_repairs: 0,
            tail_probes: 0,
        }
    }

    pub fn retry_ratio(self) -> f64 {
        if self.sent_packets == 0 {
            return 0.0;
        }
        self.retransmitted_packets as f64 / self.sent_packets as f64
    }

    pub fn quality(self) -> f64 {
        (100.0 * (1.0 - self.retry_ratio())).clamp(0.0, 100.0)
    }

    pub(crate) fn record_send(&mut self, bytes: usize) {
        self.sent_packets += 1;
        self.sent_bytes += bytes as u64;
    }

    pub(crate) fn record_retransmit(&mut self, bytes: usize) {
        self.retransmitted_packets += 1;
        self.retransmitted_bytes += bytes as u64;
    }

    pub(crate) fn record_feedback(&mut self) {
        self.feedback_packets += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReceiverStats {
    pub flow_id: u32,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub duplicate_packets: u64,
    pub recovered_packets: u64,
    pub total_missing_packets: u64,
    pub currently_missing_packets: u64,
    pub feedback_packets: u64,
    pub rtt_micros: Option<u64>,
    /// RTCP packets sent that carried a NACK (also counted in feedback_packets).
    pub nack_packets: u64,
    /// Sequences requested in NACK packets that were sent.
    pub nack_entries_sent: u64,
    /// Due sequences held back (packet limit or return-bandwidth refusal);
    /// they stay due and are requested later.
    pub nack_entries_deferred: u64,
    /// Holes still missing when they reached the recovery age.
    pub holes_expired: u64,
    /// Missing sequences beyond the 16-bit NACK horizon (never requestable).
    pub holes_unaddressable: u64,
    /// Open holes discarded by a sender restart or reconfiguration.
    pub holes_reset: u64,
    /// Packets that arrived after their hole had expired.
    pub late_packets: u64,
    /// Holes that reached max_retries NACKs.
    pub retries_exhausted: u64,
    /// Holes not requested because a NACK could no longer arrive in time.
    pub nack_too_late: u64,
    /// Data packets that carried the SSRC retry bit (retransmissions).
    pub retry_packets_received: u64,
    /// Smallest RTT sample (`rtt_micros` is the smoothed value).
    pub rtt_min_micros: Option<u64>,
    /// RTT samples from echo responses.
    pub rtt_samples_echo: u64,
    /// RTT samples from retry-marked repairs of holes NACKed once.
    pub rtt_samples_karn: u64,
    /// Echo requests sent.
    pub echo_requests_sent: u64,
    /// Originals that filled a hole (reordering samples).
    pub reorder_samples: u64,
    /// The first-NACK delay at the last poll.
    pub first_nack_delay_micros: u64,
    /// Sequences requested again in NACK copies (not attempts; also
    /// counted in nack_packets, not in nack_entries_sent).
    pub nack_copies_sent: u64,
    /// Times the highest sequence moved forward by more than half the
    /// 16-bit NACK horizon at once (a long outage, a sender restart, or a
    /// misread sequence: should stay near zero).
    pub forward_jumps: u64,
    /// Karn samples refused because they were under half the smallest
    /// echo-measured RTT (a repair that cannot answer the NACK it seems to).
    pub rtt_samples_karn_rejected: u64,
    /// Originals far behind the highest sequence that the receiver read as
    /// behind (stale) rather than as the first packet after a long gap.
    pub stale_far_behind: u64,
    /// Size of the duplicate-detection ring, in packets (it grows with the
    /// observed packet rate).
    pub duplicate_window_packets: u64,
}

impl ReceiverStats {
    pub fn new(flow_id: u32) -> Self {
        Self {
            flow_id,
            received_packets: 0,
            received_bytes: 0,
            duplicate_packets: 0,
            recovered_packets: 0,
            total_missing_packets: 0,
            currently_missing_packets: 0,
            feedback_packets: 0,
            rtt_micros: None,
            nack_packets: 0,
            nack_entries_sent: 0,
            nack_entries_deferred: 0,
            holes_expired: 0,
            holes_unaddressable: 0,
            holes_reset: 0,
            late_packets: 0,
            retries_exhausted: 0,
            nack_too_late: 0,
            retry_packets_received: 0,
            rtt_min_micros: None,
            rtt_samples_echo: 0,
            rtt_samples_karn: 0,
            echo_requests_sent: 0,
            reorder_samples: 0,
            first_nack_delay_micros: 0,
            nack_copies_sent: 0,
            forward_jumps: 0,
            rtt_samples_karn_rejected: 0,
            stale_far_behind: 0,
            duplicate_window_packets: 0,
        }
    }

    pub fn quality(self) -> f64 {
        let received_packets = self.unique_received_packets();
        let denominator = received_packets + self.currently_missing_packets;
        if denominator == 0 {
            return 100.0;
        }
        (100.0 * received_packets as f64 / denominator as f64).clamp(0.0, 100.0)
    }

    pub fn unique_received_packets(self) -> u64 {
        self.received_packets.saturating_sub(self.duplicate_packets)
    }

    pub(crate) fn record_receive(
        &mut self,
        bytes: usize,
        duplicate: bool,
        recovered: bool,
        newly_missing: usize,
        currently_missing: usize,
    ) {
        self.received_packets += 1;
        self.received_bytes += bytes as u64;
        if duplicate {
            self.duplicate_packets += 1;
        }
        if recovered {
            self.recovered_packets += 1;
        }
        self.total_missing_packets += newly_missing as u64;
        self.currently_missing_packets = currently_missing as u64;
    }

    pub(crate) fn record_feedback(&mut self) {
        self.feedback_packets += 1;
    }

    pub(crate) fn record_nack_packet(&mut self, entries: usize) {
        self.feedback_packets += 1;
        self.nack_packets += 1;
        self.nack_entries_sent += entries as u64;
    }

    pub(crate) fn apply_tracker_counters(&mut self, counters: crate::recovery::TrackerCounters) {
        self.holes_expired = counters.holes_expired;
        self.holes_unaddressable = counters.holes_unaddressable;
        self.holes_reset = counters.holes_reset;
        self.late_packets = counters.late_packets;
        self.retries_exhausted = counters.retries_exhausted;
        self.nack_too_late = counters.nack_too_late;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_quality_tracks_retries() {
        let mut stats = SenderStats::new(1);
        stats.record_send(100);
        stats.record_send(100);
        stats.record_retransmit(100);
        assert_eq!(stats.retry_ratio(), 0.5);
        assert_eq!(stats.quality(), 50.0);
    }

    #[test]
    fn receiver_quality_tracks_current_holes() {
        let mut stats = ReceiverStats::new(1);
        stats.record_receive(100, false, false, 0, 0);
        stats.record_receive(100, false, false, 2, 2);
        assert_eq!(stats.total_missing_packets, 2);
        assert_eq!(stats.quality(), 50.0);
        stats.record_receive(100, false, true, 0, 1);
        assert_eq!(stats.recovered_packets, 1);
        assert_eq!(stats.quality(), 75.0);
    }

    #[test]
    fn receiver_quality_excludes_duplicate_packets() {
        let mut stats = ReceiverStats::new(1);
        stats.record_receive(100, false, false, 0, 0);
        stats.record_receive(100, true, false, 0, 0);
        stats.record_receive(100, false, false, 1, 1);

        assert_eq!(stats.received_packets, 3);
        assert_eq!(stats.duplicate_packets, 1);
        assert_eq!(stats.unique_received_packets(), 2);
        assert_eq!(stats.quality(), 100.0 * 2.0 / 3.0);
    }
}
