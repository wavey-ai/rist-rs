use crate::ReceivedPayload;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct SavedPacket {
    pub sequence: u32,
    pub inserted_at: Instant,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderHistory {
    max_packets: usize,
    packets: BTreeMap<u32, SavedPacket>,
}

/// Restores wire order before a recovered RIST payload is exposed as bytes.
///
/// [`ReceivedPayload`] reports arrival order so protocol users can inspect
/// duplicates and recovery events. Byte-stream consumers must additionally
/// hold later packets behind a sequence gap; otherwise a retransmission is
/// appended after the data that followed it and corrupts the reconstructed
/// stream.
#[derive(Debug, Clone)]
pub struct OrderedPayloadBuffer {
    next_sequence: Option<u32>,
    pending: BTreeMap<u32, ReceivedPayload>,
    max_pending_packets: usize,
}

impl OrderedPayloadBuffer {
    pub fn new(max_pending_packets: usize) -> Self {
        Self {
            next_sequence: None,
            pending: BTreeMap::new(),
            max_pending_packets: max_pending_packets.max(1),
        }
    }

    /// Inserts one arrival and returns every newly contiguous payload in wire
    /// order. Already delivered and bonded-path duplicate packets are ignored.
    ///
    /// The buffer fails closed when a gap grows beyond its configured bound.
    /// Continuing by concatenating bytes across an unresolved gap would turn
    /// packet loss into silent stream corruption.
    pub fn push(
        &mut self,
        payload: ReceivedPayload,
    ) -> Result<Vec<ReceivedPayload>, OrderedPayloadBufferError> {
        if payload.duplicate {
            return Ok(Vec::new());
        }

        let sequence = payload.sequence;
        let next_sequence = *self.next_sequence.get_or_insert(sequence);
        if self.pending.contains_key(&sequence) {
            return Ok(Vec::new());
        }

        self.pending.insert(sequence, payload);

        let mut ready = Vec::new();
        let mut next = next_sequence;
        while let Some(payload) = self.pending.remove(&next) {
            ready.push(payload);
            next = next.wrapping_add(1);
        }
        self.next_sequence = Some(next);

        if self.pending.len() > self.max_pending_packets {
            self.pending.remove(&sequence);
            return Err(OrderedPayloadBufferError {
                next_sequence: next,
                received_sequence: sequence,
                max_pending_packets: self.max_pending_packets,
            });
        }

        Ok(ready)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn next_sequence(&self) -> Option<u32> {
        self.next_sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedPayloadBufferError {
    pub next_sequence: u32,
    pub received_sequence: u32,
    pub max_pending_packets: usize,
}

impl fmt::Display for OrderedPayloadBufferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RIST reorder buffer exceeded {} packets while waiting for sequence {} (received {})",
            self.max_pending_packets, self.next_sequence, self.received_sequence
        )
    }
}

impl Error for OrderedPayloadBufferError {}

impl SenderHistory {
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            packets: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, sequence: u32, payload: impl Into<Vec<u8>>, now: Instant) {
        self.packets.insert(
            sequence,
            SavedPacket {
                sequence,
                inserted_at: now,
                payload: payload.into(),
            },
        );

        while self.packets.len() > self.max_packets {
            if let Some(oldest) = self.packets.keys().next().copied() {
                self.packets.remove(&oldest);
            }
        }
    }

    pub fn get(&self, sequence: u32) -> Option<&SavedPacket> {
        self.packets.get(&sequence)
    }

    pub fn resolve_nacks<'a>(
        &'a self,
        sequences: impl IntoIterator<Item = u32>,
    ) -> Vec<&'a SavedPacket> {
        sequences
            .into_iter()
            .filter_map(|sequence| self.get(sequence))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverObservation {
    pub sequence: u32,
    pub duplicate: bool,
    pub recovered: bool,
    pub newly_missing: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct MissingTracker {
    next_expected: Option<u32>,
    missing: BTreeSet<u32>,
    delivered: BTreeSet<u32>,
}

impl MissingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, sequence: u32) -> ReceiverObservation {
        let duplicate = !self.delivered.insert(sequence);
        let recovered = self.missing.remove(&sequence);
        let mut newly_missing = Vec::new();

        if !duplicate && !recovered {
            if let Some(next) = self.next_expected {
                if sequence > next {
                    for missing in next..sequence {
                        if self.delivered.contains(&missing) {
                            continue;
                        }
                        if self.missing.insert(missing) {
                            newly_missing.push(missing);
                        }
                    }
                }
            }
        }

        match self.next_expected {
            Some(next) if sequence >= next => self.next_expected = Some(sequence + 1),
            None => self.next_expected = Some(sequence + 1),
            _ => {}
        }

        ReceiverObservation {
            sequence,
            duplicate,
            recovered,
            newly_missing,
        }
    }

    pub fn missing_sequences(&self) -> impl Iterator<Item = u32> + '_ {
        self.missing.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(sequence: u32, value: u8) -> ReceivedPayload {
        ReceivedPayload {
            sequence,
            recovered: false,
            duplicate: false,
            newly_missing: Vec::new(),
            payload: vec![value],
        }
    }

    #[test]
    fn tracks_gaps_and_recovery() {
        let mut tracker = MissingTracker::new();
        assert!(tracker.observe(10).newly_missing.is_empty());
        assert_eq!(tracker.observe(13).newly_missing, vec![11, 12]);
        assert_eq!(
            tracker.missing_sequences().collect::<Vec<_>>(),
            vec![11, 12]
        );
        let recovered = tracker.observe(11);
        assert!(recovered.recovered);
        assert_eq!(tracker.missing_sequences().collect::<Vec<_>>(), vec![12]);
    }

    #[test]
    fn sender_history_evicts_oldest_sequence() {
        let now = Instant::now();
        let mut history = SenderHistory::new(2);
        history.insert(1, [1], now);
        history.insert(2, [2], now);
        history.insert(3, [3], now);
        assert!(history.get(1).is_none());
        assert_eq!(history.get(2).unwrap().payload, vec![2]);
    }

    #[test]
    fn ordered_payload_buffer_holds_a_gap_until_recovery() {
        let mut buffer = OrderedPayloadBuffer::new(8);

        assert_eq!(buffer.push(payload(10, 10)).unwrap(), vec![payload(10, 10)]);
        assert!(buffer.push(payload(12, 12)).unwrap().is_empty());
        assert_eq!(buffer.pending_len(), 1);
        assert_eq!(
            buffer.push(payload(11, 11)).unwrap(),
            vec![payload(11, 11), payload(12, 12)]
        );
        assert_eq!(buffer.pending_len(), 0);
        assert_eq!(buffer.next_sequence(), Some(13));
    }

    #[test]
    fn ordered_payload_buffer_suppresses_arrival_duplicates() {
        let mut buffer = OrderedPayloadBuffer::new(8);
        assert_eq!(buffer.push(payload(20, 20)).unwrap(), vec![payload(20, 20)]);

        let mut duplicate = payload(20, 20);
        duplicate.duplicate = true;
        assert!(buffer.push(duplicate).unwrap().is_empty());
        assert_eq!(buffer.next_sequence(), Some(21));
    }

    #[test]
    fn ordered_payload_buffer_fails_closed_at_its_bound() {
        let mut buffer = OrderedPayloadBuffer::new(2);
        assert_eq!(buffer.push(payload(30, 30)).unwrap(), vec![payload(30, 30)]);
        assert!(buffer.push(payload(32, 32)).unwrap().is_empty());
        assert!(buffer.push(payload(33, 33)).unwrap().is_empty());

        let error = buffer.push(payload(34, 34)).unwrap_err();
        assert_eq!(error.next_sequence, 31);
        assert_eq!(error.received_sequence, 34);
        assert_eq!(buffer.pending_len(), 2);
    }
}
