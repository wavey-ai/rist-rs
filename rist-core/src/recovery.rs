use std::collections::{BTreeMap, BTreeSet};
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
}
