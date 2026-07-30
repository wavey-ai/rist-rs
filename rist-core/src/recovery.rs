use crate::ReceivedPayload;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

pub const DEFAULT_RECEIVER_WINDOW_PACKETS: usize = 8_192;
pub const DEFAULT_RECOVERY_AGE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct SavedPacket {
    pub sequence: u32,
    pub inserted_at: Instant,
    pub retry_count: u32,
    pub last_retry_at: Option<Instant>,
    pub payload_len: usize,
    /// Exact bytes accepted for transmission. Retries must reuse this buffer.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderHistory {
    slots: Vec<Option<SavedPacket>>,
    mask: usize,
    len: usize,
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
    pending: BTreeMap<u32, PendingPayload>,
    max_pending_packets: usize,
    reorder_delay: Duration,
}

#[derive(Debug, Clone)]
struct PendingPayload {
    arrival: Instant,
    payload: ReceivedPayload,
}

impl OrderedPayloadBuffer {
    pub fn new(max_pending_packets: usize) -> Self {
        Self::with_reorder_delay(max_pending_packets, Duration::MAX)
    }

    pub fn with_reorder_delay(max_pending_packets: usize, reorder_delay: Duration) -> Self {
        Self {
            next_sequence: None,
            pending: BTreeMap::new(),
            max_pending_packets: max_pending_packets.max(1),
            reorder_delay,
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
        self.push_at(payload, Instant::now())
    }

    pub fn push_at(
        &mut self,
        payload: ReceivedPayload,
        now: Instant,
    ) -> Result<Vec<ReceivedPayload>, OrderedPayloadBufferError> {
        if payload.duplicate {
            return Ok(Vec::new());
        }

        let sequence = payload.sequence;
        let next_sequence = *self.next_sequence.get_or_insert(sequence);
        if self.pending.contains_key(&sequence) {
            return Ok(Vec::new());
        }

        self.pending.insert(
            sequence,
            PendingPayload {
                arrival: now,
                payload,
            },
        );

        let mut ready = self.drain_contiguous(next_sequence);

        if self.pending.len() > self.max_pending_packets {
            self.pending.remove(&sequence);
            return Err(OrderedPayloadBufferError {
                next_sequence: self.next_sequence.unwrap_or(next_sequence),
                received_sequence: sequence,
                max_pending_packets: self.max_pending_packets,
            });
        }

        if ready.is_empty() {
            ready.extend(self.release_expired(now));
        }
        Ok(ready)
    }

    /// Releases the earliest packet after its reorder deadline and then drains
    /// all contiguous successors. This turns an unrecoverable gap into an
    /// explicit deadline decision rather than an indefinitely growing buffer.
    pub fn release_expired(&mut self, now: Instant) -> Vec<ReceivedPayload> {
        let Some(next) = self.next_sequence else {
            return Vec::new();
        };
        let Some((&sequence, pending)) = self
            .pending
            .iter()
            .filter(|(sequence, _)| sequence.wrapping_sub(next) < (1 << 31))
            .min_by_key(|(sequence, _)| sequence.wrapping_sub(next))
        else {
            return Vec::new();
        };
        if now.saturating_duration_since(pending.arrival) < self.reorder_delay {
            return Vec::new();
        }
        self.next_sequence = Some(sequence);
        self.drain_contiguous(sequence)
    }

    fn drain_contiguous(&mut self, start: u32) -> Vec<ReceivedPayload> {
        let mut ready = Vec::new();
        let mut next = start;
        while let Some(pending) = self.pending.remove(&next) {
            ready.push(pending.payload);
            next = next.wrapping_add(1);
        }
        self.next_sequence = Some(next);
        ready
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
        let capacity = if max_packets == 0 {
            0
        } else {
            max_packets.next_power_of_two()
        };
        Self {
            slots: vec![None; capacity],
            mask: capacity.saturating_sub(1),
            len: 0,
        }
    }

    pub fn insert(&mut self, sequence: u32, payload: impl Into<Vec<u8>>, now: Instant) {
        if self.slots.is_empty() {
            return;
        }
        let payload = payload.into();
        let slot = &mut self.slots[sequence as usize & self.mask];
        if slot.is_none() {
            self.len += 1;
        }
        *slot = Some(SavedPacket {
            sequence,
            inserted_at: now,
            retry_count: 0,
            last_retry_at: None,
            payload_len: payload.len(),
            payload,
        });
    }

    pub fn get(&self, sequence: u32) -> Option<&SavedPacket> {
        self.slots
            .get(sequence as usize & self.mask)?
            .as_ref()
            .filter(|packet| packet.sequence == sequence)
    }

    pub fn get_mut(&mut self, sequence: u32) -> Option<&mut SavedPacket> {
        self.slots
            .get_mut(sequence as usize & self.mask)?
            .as_mut()
            .filter(|packet| packet.sequence == sequence)
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn resolve_nacks(&self, sequences: impl IntoIterator<Item = u32>) -> Vec<&SavedPacket> {
        sequences
            .into_iter()
            .filter_map(|sequence| self.get(sequence))
            .collect()
    }

    pub fn take_retry(
        &mut self,
        sequence: u32,
        now: Instant,
        minimum_spacing: Duration,
        maximum_age: Duration,
        maximum_retries: u32,
    ) -> Option<SavedPacket> {
        let packet = self.get_mut(sequence)?;
        if now.saturating_duration_since(packet.inserted_at) > maximum_age
            || packet.retry_count >= maximum_retries
            || packet
                .last_retry_at
                .is_some_and(|last| now.saturating_duration_since(last) < minimum_spacing)
        {
            return None;
        }
        packet.retry_count += 1;
        packet.last_retry_at = Some(now);
        Some(packet.clone())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverObservation {
    pub sequence: u32,
    pub duplicate: bool,
    pub recovered: bool,
    pub newly_missing: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct MissingTracker {
    slots: Vec<SequenceWindowSlot>,
    mask: usize,
    highest: Option<u32>,
    recovery_age: Duration,
    missing_count: usize,
}

#[derive(Debug, Clone)]
struct SequenceWindowSlot {
    sequence: u32,
    state: SequenceState,
}

#[derive(Debug, Clone)]
enum SequenceState {
    Vacant,
    Delivered,
    Missing {
        first_missing_at: Instant,
        last_nack_at: Option<Instant>,
        nack_count: u32,
    },
}

impl Default for MissingTracker {
    fn default() -> Self {
        Self::with_limits(DEFAULT_RECEIVER_WINDOW_PACKETS, DEFAULT_RECOVERY_AGE)
    }
}

impl MissingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, sequence: u32) -> ReceiverObservation {
        self.observe_at(sequence, Instant::now())
    }

    pub fn with_limits(window_packets: usize, recovery_age: Duration) -> Self {
        let capacity = window_packets.max(2).next_power_of_two();
        Self {
            slots: (0..capacity)
                .map(|_| SequenceWindowSlot {
                    sequence: 0,
                    state: SequenceState::Vacant,
                })
                .collect(),
            mask: capacity - 1,
            highest: None,
            recovery_age,
            missing_count: 0,
        }
    }

    pub fn observe_at(&mut self, sequence: u32, now: Instant) -> ReceiverObservation {
        self.expire(now);
        let mut newly_missing = Vec::new();
        let mut duplicate = false;
        let mut recovered = false;

        match self.highest {
            None => {
                self.highest = Some(sequence);
            }
            Some(highest) => {
                let distance = sequence.wrapping_sub(highest);
                if distance != 0 && distance < (1 << 31) {
                    let missing_to_add = usize::try_from(distance.saturating_sub(1))
                        .unwrap_or(usize::MAX)
                        .min(self.slots.len().saturating_sub(1));
                    let first = sequence.wrapping_sub(missing_to_add as u32);
                    for offset in 0..missing_to_add {
                        let missing = first.wrapping_add(offset as u32);
                        if self.mark_missing(missing, now) {
                            newly_missing.push(missing);
                        }
                    }
                    self.highest = Some(sequence);
                } else if distance >= (1 << 31)
                    && highest.wrapping_sub(sequence) as usize >= self.slots.len()
                {
                    return ReceiverObservation {
                        sequence,
                        duplicate: true,
                        recovered: false,
                        newly_missing,
                    };
                }
            }
        }

        let index = sequence as usize & self.mask;
        let slot = &mut self.slots[index];
        if slot.sequence == sequence {
            match slot.state {
                SequenceState::Delivered => duplicate = true,
                SequenceState::Missing { .. } => {
                    recovered = true;
                    self.missing_count = self.missing_count.saturating_sub(1);
                }
                SequenceState::Vacant => {}
            }
        } else if matches!(slot.state, SequenceState::Missing { .. }) {
            self.missing_count = self.missing_count.saturating_sub(1);
        }
        slot.sequence = sequence;
        slot.state = SequenceState::Delivered;

        ReceiverObservation {
            sequence,
            duplicate,
            recovered,
            newly_missing,
        }
    }

    pub fn missing_sequences(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots.iter().filter_map(|slot| {
            matches!(slot.state, SequenceState::Missing { .. }).then_some(slot.sequence)
        })
    }

    pub fn missing_len(&self) -> usize {
        self.missing_count
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.state = SequenceState::Vacant;
        }
        self.highest = None;
        self.missing_count = 0;
    }

    pub fn nacks_due(
        &mut self,
        now: Instant,
        initial_delay: Duration,
        repeat_delay: Duration,
        min_retries: u32,
        max_retries: u32,
    ) -> Vec<u32> {
        self.expire(now);
        let mut due = Vec::with_capacity(self.missing_count);
        for slot in &mut self.slots {
            let SequenceState::Missing {
                first_missing_at,
                last_nack_at,
                nack_count,
            } = &mut slot.state
            else {
                continue;
            };
            if *nack_count >= max_retries {
                continue;
            }
            let delay = if last_nack_at.is_some() {
                repeat_delay
            } else {
                initial_delay
            };
            let reference = last_nack_at.unwrap_or(*first_missing_at);
            if now.saturating_duration_since(reference) < delay {
                continue;
            }
            // The configured minimum controls the guaranteed attempts; after
            // that, requests continue only while the packet remains inside
            // the fixed recovery-age window, up to max_retries.
            if *nack_count < min_retries
                || now.duration_since(*first_missing_at) < self.recovery_age
            {
                due.push(slot.sequence);
                *nack_count += 1;
                *last_nack_at = Some(now);
            }
        }
        due.sort_unstable_by_key(|sequence| {
            self.highest.unwrap_or(*sequence).wrapping_sub(*sequence)
        });
        due
    }

    fn mark_missing(&mut self, sequence: u32, now: Instant) -> bool {
        let index = sequence as usize & self.mask;
        let slot = &mut self.slots[index];
        if slot.sequence == sequence && !matches!(slot.state, SequenceState::Vacant) {
            return false;
        }
        if matches!(slot.state, SequenceState::Missing { .. }) {
            self.missing_count = self.missing_count.saturating_sub(1);
        }
        slot.sequence = sequence;
        slot.state = SequenceState::Missing {
            first_missing_at: now,
            last_nack_at: None,
            nack_count: 0,
        };
        self.missing_count += 1;
        true
    }

    fn expire(&mut self, now: Instant) {
        for slot in &mut self.slots {
            let expired = match slot.state {
                SequenceState::Missing {
                    first_missing_at, ..
                } => now.saturating_duration_since(first_missing_at) >= self.recovery_age,
                _ => false,
            };
            if expired {
                slot.state = SequenceState::Vacant;
                self.missing_count = self.missing_count.saturating_sub(1);
            }
        }
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
    fn sender_history_is_bounded_and_correct_across_u32_rollover() {
        let now = Instant::now();
        let mut history = SenderHistory::new(4);
        for sequence in [u32::MAX - 1, u32::MAX, 0, 1, 2] {
            history.insert(sequence, sequence.to_be_bytes(), now);
        }
        assert_eq!(history.capacity(), 4);
        assert!(history.get(u32::MAX - 1).is_none());
        for sequence in [u32::MAX, 0, 1, 2] {
            assert_eq!(history.get(sequence).unwrap().sequence, sequence);
        }
    }

    #[test]
    fn receiver_window_bounds_large_gaps_and_expires_missing_state() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(8, Duration::from_millis(100));
        tracker.observe_at(10, start);
        let observation = tracker.observe_at(1_000_000, start);
        assert_eq!(observation.newly_missing.len(), 7);
        assert_eq!(tracker.capacity(), 8);
        assert_eq!(tracker.missing_len(), 7);

        tracker.observe_at(1_000_001, start + Duration::from_millis(101));
        assert_eq!(tracker.missing_len(), 0);
    }

    #[test]
    fn missing_window_and_deadlines_cross_u32_rollover() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(8, Duration::from_secs(1));
        tracker.observe_at(u32::MAX - 1, start);
        let observation = tracker.observe_at(1, start);
        assert_eq!(observation.newly_missing, vec![u32::MAX, 0]);
        let recovered = tracker.observe_at(0, start);
        assert!(recovered.recovered);
        assert_eq!(
            tracker.missing_sequences().collect::<Vec<_>>(),
            vec![u32::MAX]
        );
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

    #[test]
    fn ordered_payload_buffer_releases_an_expired_gap_across_rollover() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(8, Duration::from_millis(10));
        assert_eq!(
            buffer.push_at(payload(u32::MAX, 1), start).unwrap(),
            vec![payload(u32::MAX, 1)]
        );
        assert!(buffer.push_at(payload(1, 3), start).unwrap().is_empty());
        assert_eq!(
            buffer.release_expired(start + Duration::from_millis(10)),
            vec![payload(1, 3)]
        );
        assert_eq!(buffer.next_sequence(), Some(2));
    }
}
