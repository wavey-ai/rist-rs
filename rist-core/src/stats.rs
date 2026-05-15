#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SenderStats {
    pub flow_id: u32,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub retransmitted_packets: u64,
    pub retransmitted_bytes: u64,
    pub feedback_packets: u64,
    pub rtt_micros: Option<u64>,
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

    pub(crate) fn set_rtt_micros(&mut self, rtt_micros: u64) {
        self.rtt_micros = Some(rtt_micros);
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
