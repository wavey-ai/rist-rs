use crate::ReceivedPayload;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};
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

/// The most packets a sender history grows to by time: requests carry
/// 16-bit sequences that the sender extends near the newest sequence sent,
/// so nothing more than 2^15 behind it can ever be named.
pub const MAX_ADDRESSABLE_HISTORY: usize = 1 << 15;

#[derive(Debug, Clone)]
pub struct SenderHistory {
    slots: Vec<Option<SavedPacket>>,
    mask: usize,
    len: usize,
    retention: Duration,
    max_packets: usize,
}

/// Restores wire order before a recovered RIST payload is exposed as bytes.
///
/// [`ReceivedPayload`] reports arrival order so protocol users can inspect
/// duplicates and recovery events. Byte-stream consumers must additionally
/// hold later packets behind a sequence gap; otherwise a retransmission is
/// appended after the data that followed it and corrupts the reconstructed
/// stream.
///
/// Sequences are extended to 64 bits relative to the release point, so the
/// buffer is a `BTreeMap` walk (O(log n) per packet) and crosses the u32
/// rollover like any other sequence. An in-order packet with nothing held
/// takes a fast path that touches no map.
///
/// A packet behind the release point (a repair that arrives after its gap
/// was skipped, or a copy of a packet already released) is dropped and
/// counted as late; it is never held.
#[derive(Debug, Clone)]
pub struct OrderedPayloadBuffer {
    /// The next extended sequence to release.
    next: Option<u64>,
    /// Held payloads by extended sequence; every key is above `next`.
    /// Arrivals are non-decreasing in key: a payload inserted before a held
    /// one takes the earlier arrival, so the first entry's arrival is when
    /// the gap at `next` was first seen.
    pending: BTreeMap<u64, PendingPayload>,
    max_pending_packets: usize,
    reorder_delay: Duration,
    overflow: OverflowPolicy,
    stats: OrderedStats,
}

#[derive(Debug, Clone)]
struct PendingPayload {
    arrival: Instant,
    payload: ReceivedPayload,
}

/// What an [`OrderedPayloadBuffer`] does when more than its bound is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Refuse the packet with [`OrderedPayloadBufferError`] (after first
    /// releasing any gap whose deadline has passed). The behaviour of
    /// [`OrderedPayloadBuffer::new`] and
    /// [`OrderedPayloadBuffer::with_reorder_delay`].
    FailClosed,
    /// Skip the oldest gap (counted in [`OrderedStats`]) until the bound
    /// holds again, so a push never fails. The behaviour of
    /// [`OrderedPayloadBuffer::with_deadline`].
    SkipOldestGap,
}

/// What happened to one pushed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedPush {
    /// The payload, or a gap's deadline, released at least one payload.
    Released,
    /// Held behind a gap; nothing was released.
    Held,
    /// Already held, or flagged as a duplicate by the receiver: dropped.
    Duplicate,
    /// Behind the release point: dropped and counted in
    /// [`OrderedStats::late_dropped`].
    Late,
}

/// Counters of an [`OrderedPayloadBuffer`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrderedStats {
    /// Payloads released in order.
    pub released: u64,
    /// Gaps given up (at their deadline, at the bound, or by `flush_all`).
    pub gaps_skipped: u64,
    /// Sequences inside the skipped gaps.
    pub packets_skipped: u64,
    /// Payloads that arrived behind the release point and were dropped.
    pub late_dropped: u64,
    /// Payloads dropped as duplicates.
    pub duplicates: u64,
    /// The most payloads held at once.
    pub held_max: u64,
}

impl OrderedPayloadBuffer {
    /// Holds gaps without a deadline and fails closed past
    /// `max_pending_packets` held payloads.
    pub fn new(max_pending_packets: usize) -> Self {
        Self::with_reorder_delay(max_pending_packets, Duration::MAX)
    }

    /// Skips a gap once the first payload after it has waited
    /// `reorder_delay`, and fails closed past `max_pending_packets` held
    /// payloads when no gap is due.
    pub fn with_reorder_delay(max_pending_packets: usize, reorder_delay: Duration) -> Self {
        Self::with_policy(
            max_pending_packets,
            reorder_delay,
            OverflowPolicy::FailClosed,
        )
    }

    /// Skips a gap once the first payload after it has waited
    /// `reorder_delay`, and skips the oldest gap instead of failing when
    /// more than `max_pending_packets` are held: pushes never fail. Use it
    /// for a byte stream that should carry on past an unrecoverable loss
    /// (an MPEG-TS demuxer sees a continuity-counter jump, as with librist).
    pub fn with_deadline(max_pending_packets: usize, reorder_delay: Duration) -> Self {
        Self::with_policy(
            max_pending_packets,
            reorder_delay,
            OverflowPolicy::SkipOldestGap,
        )
    }

    pub fn with_policy(
        max_pending_packets: usize,
        reorder_delay: Duration,
        overflow: OverflowPolicy,
    ) -> Self {
        Self {
            next: None,
            pending: BTreeMap::new(),
            max_pending_packets: max_pending_packets.max(1),
            reorder_delay,
            overflow,
            stats: OrderedStats::default(),
        }
    }

    /// Inserts one arrival and returns every newly contiguous payload in wire
    /// order. Already delivered and bonded-path duplicate packets are ignored.
    ///
    /// With [`OverflowPolicy::FailClosed`] the buffer fails closed when a gap
    /// grows beyond its configured bound. Continuing by concatenating bytes
    /// across an unresolved gap would turn packet loss into silent stream
    /// corruption.
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
        let mut ready = Vec::new();
        self.push_into(payload, now, &mut ready)?;
        Ok(ready)
    }

    /// [`Self::push_at`] appending to `out`, so a caller that reuses `out`
    /// allocates nothing per packet. On `Err` nothing was appended.
    pub fn push_into(
        &mut self,
        payload: ReceivedPayload,
        now: Instant,
        out: &mut Vec<ReceivedPayload>,
    ) -> Result<OrderedPush, OrderedPayloadBufferError> {
        if payload.duplicate {
            self.stats.duplicates += 1;
            return Ok(OrderedPush::Duplicate);
        }
        let sequence = payload.sequence;
        let next = *self.next.get_or_insert(u64::from(sequence) + (1u64 << 32));
        let distance = sequence.wrapping_sub(next as u32);
        if distance >= 1 << 31 {
            self.stats.late_dropped += 1;
            return Ok(OrderedPush::Late);
        }
        if distance == 0 && self.pending.is_empty() {
            out.push(payload);
            self.next = Some(next + 1);
            self.stats.released += 1;
            return Ok(OrderedPush::Released);
        }
        let key = next + u64::from(distance);
        if self.pending.contains_key(&key) {
            self.stats.duplicates += 1;
            return Ok(OrderedPush::Duplicate);
        }
        let arrival = self
            .pending
            .range(key..)
            .next()
            .map_or(now, |(_, held)| held.arrival.min(now));
        self.pending
            .insert(key, PendingPayload { arrival, payload });
        self.stats.held_max = self.stats.held_max.max(self.pending.len() as u64);

        let before = out.len();
        self.drain_into(out);
        if self.pending.len() > self.max_pending_packets {
            // A gap whose deadline has passed is skipped before the bound
            // decides.
            self.release_expired_into(now, out);
        }
        while self.pending.len() > self.max_pending_packets {
            match self.overflow {
                OverflowPolicy::FailClosed => {
                    // Nothing was released: a release would have shrunk
                    // `pending` back under the bound.
                    self.pending.remove(&key);
                    return Err(OrderedPayloadBufferError {
                        next_sequence: self.next.unwrap_or(next) as u32,
                        received_sequence: sequence,
                        max_pending_packets: self.max_pending_packets,
                    });
                }
                OverflowPolicy::SkipOldestGap => {
                    self.skip_to_first(out);
                }
            }
        }
        if out.len() == before {
            self.release_expired_into(now, out);
        }
        Ok(if out.len() > before {
            OrderedPush::Released
        } else {
            OrderedPush::Held
        })
    }

    /// Skips every gap whose first held successor has waited the reorder
    /// delay, and drains what follows each: several expired gaps go in one
    /// call. O(log n) per gap.
    pub fn release_expired(&mut self, now: Instant) -> Vec<ReceivedPayload> {
        let mut ready = Vec::new();
        self.release_expired_into(now, &mut ready);
        ready
    }

    /// [`Self::release_expired`] appending to `out`. Returns the number of
    /// sequences skipped.
    pub fn release_expired_into(&mut self, now: Instant, out: &mut Vec<ReceivedPayload>) -> u64 {
        let mut skipped = 0;
        while let Some((_, held)) = self.pending.first_key_value() {
            if now.saturating_duration_since(held.arrival) < self.reorder_delay {
                break;
            }
            skipped += self.skip_to_first(out);
        }
        skipped
    }

    /// Releases everything held in order, skipping every gap (counted): for
    /// the end of a stream.
    pub fn flush_all(&mut self) -> Vec<ReceivedPayload> {
        let mut ready = Vec::new();
        self.flush_all_into(&mut ready);
        ready
    }

    pub fn flush_all_into(&mut self, out: &mut Vec<ReceivedPayload>) -> u64 {
        let mut skipped = 0;
        while !self.pending.is_empty() {
            skipped += self.skip_to_first(out);
        }
        skipped
    }

    /// When [`Self::release_expired`] next skips a gap: the arrival of the
    /// first payload after the gap plus the reorder delay. `None` when
    /// nothing is held or the delay is unbounded.
    pub fn next_deadline(&self) -> Option<Instant> {
        let (_, held) = self.pending.first_key_value()?;
        held.arrival.checked_add(self.reorder_delay)
    }

    /// Moves the release point to the first held payload and drains from
    /// there. Returns the sequences skipped.
    fn skip_to_first(&mut self, out: &mut Vec<ReceivedPayload>) -> u64 {
        let Some((&first, _)) = self.pending.first_key_value() else {
            return 0;
        };
        let next = self.next.unwrap_or(first);
        let skipped = first.saturating_sub(next);
        if skipped > 0 {
            self.stats.gaps_skipped += 1;
            self.stats.packets_skipped += skipped;
        }
        self.next = Some(first);
        self.drain_into(out);
        skipped
    }

    fn drain_into(&mut self, out: &mut Vec<ReceivedPayload>) {
        let Some(mut next) = self.next else {
            return;
        };
        while let Some(entry) = self.pending.first_entry() {
            if *entry.key() != next {
                break;
            }
            out.push(entry.remove().payload);
            self.stats.released += 1;
            next += 1;
        }
        self.next = Some(next);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn next_sequence(&self) -> Option<u32> {
        self.next.map(|next| next as u32)
    }

    pub fn reorder_delay(&self) -> Duration {
        self.reorder_delay
    }

    pub fn overflow_policy(&self) -> OverflowPolicy {
        self.overflow
    }

    pub fn stats(&self) -> OrderedStats {
        self.stats
    }

    /// Sequences given up inside skipped gaps.
    pub fn skipped_packets(&self) -> u64 {
        self.stats.packets_skipped
    }

    pub fn gaps_skipped(&self) -> u64 {
        self.stats.gaps_skipped
    }

    /// Payloads dropped because they arrived behind the release point.
    pub fn late_dropped(&self) -> u64 {
        self.stats.late_dropped
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
            retention: Duration::ZERO,
            max_packets: capacity,
        }
    }

    /// Keeps every packet for at least `retention` after it was sent: an
    /// insert that would evict a younger packet doubles the history first,
    /// up to `max_packets` (rounded up to a power of two), and never past
    /// [`MAX_ADDRESSABLE_HISTORY`]: a NACK names 16-bit sequences, so a
    /// packet further behind the newest cannot be requested and a larger
    /// table would only hold memory. Zero retention (the default) keeps the
    /// fixed packet count of [`Self::new`], which is never shrunk. A
    /// history created with zero packets stays disabled.
    pub fn set_retention(&mut self, retention: Duration, max_packets: usize) {
        self.retention = retention;
        self.max_packets = max_packets
            .min(MAX_ADDRESSABLE_HISTORY)
            .max(self.slots.len());
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }

    pub fn insert(&mut self, sequence: u32, payload: impl Into<Vec<u8>>, now: Instant) {
        if self.slots.is_empty() {
            return;
        }
        while self.evicts_young(sequence, now) && self.slots.len() < self.max_packets {
            self.grow();
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

    fn evicts_young(&self, sequence: u32, now: Instant) -> bool {
        !self.retention.is_zero()
            && self.slots[sequence as usize & self.mask]
                .as_ref()
                .is_some_and(|old| {
                    old.sequence != sequence
                        && now.saturating_duration_since(old.inserted_at) < self.retention
                })
    }

    /// Doubles the slot table. Entries keep their low bits, so no two land
    /// on the same new slot.
    fn grow(&mut self) {
        let capacity = self.slots.len() * 2;
        let mask = capacity - 1;
        let mut slots = vec![None; capacity];
        for packet in self.slots.drain(..).flatten() {
            let index = packet.sequence as usize & mask;
            slots[index] = Some(packet);
        }
        self.slots = slots;
        self.mask = mask;
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

/// The furthest a hole may lie behind the highest received sequence and still
/// be tracked.
///
/// NACK records carry only the low 16 bits of a sequence and the sender maps
/// them back next to its own newest sequence, so a hole more than 32767 behind
/// cannot be requested unambiguously. Holes beyond this horizon are counted in
/// [`TrackerCounters::holes_unaddressable`], never dropped silently.
pub const MAX_TRACKED_HOLE_DISTANCE: u32 = 0x7fff;

/// Upper bound of the duplicate-detection ring of a [`MissingTracker`].
pub const MAX_RECEIVER_WINDOW_PACKETS: usize = 1 << 20;

/// Cumulative hole accounting of a [`MissingTracker`]. Every hole that is
/// opened leaves through exactly one of: recovery, expiry, the address
/// horizon, or a reset; each is counted. The counters survive
/// [`MissingTracker::reset`] and [`MissingTracker::reconfigure`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackerCounters {
    /// Holes opened (sequences detected as missing and tracked).
    pub holes_opened: u64,
    /// Holes closed by the arrival of their packet.
    pub holes_recovered: u64,
    /// Holes still missing when they reached the recovery age.
    pub holes_expired: u64,
    /// Missing sequences more than [`MAX_TRACKED_HOLE_DISTANCE`] behind the
    /// highest sequence: the part of a gap beyond the horizon, and open holes
    /// pushed past it by later packets.
    pub holes_unaddressable: u64,
    /// Open holes discarded by a reset (sender SSRC change or reconfiguration).
    pub holes_reset: u64,
    /// Packets that arrived after their hole had expired or left the horizon
    /// (neither duplicates nor recoveries).
    pub late_packets: u64,
    /// Holes that reached `max_retries` NACKs and are no longer requested.
    pub retries_exhausted: u64,
    /// Holes no longer requested because a NACK could not arrive in time.
    pub nack_too_late: u64,
}

/// NACK selection policy for one pass of [`MissingTracker::take_due_nacks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackSchedule {
    /// Delay from detection to the first NACK of a hole (the reorder buffer).
    pub initial_delay: Duration,
    /// Delay between NACKs of the same hole. Used by the compatibility wrapper
    /// [`MissingTracker::nacks_due`]; callers of the split API pass the repeat
    /// delay to [`MissingTracker::commit_nacks`] per batch.
    pub repeat_delay: Duration,
    /// Holes that already received this many NACKs are not requested again.
    pub max_retries: u32,
    /// A hole is no longer requested when less than this is left before its
    /// recovery deadline (detection + recovery age). Zero disables the check.
    pub min_time_left: Duration,
}

impl Default for NackSchedule {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(15),
            repeat_delay: Duration::from_millis(5),
            max_retries: 20,
            min_time_left: Duration::ZERO,
        }
    }
}

/// When the next NACK of a hole is due after one was sent; see
/// [`MissingTracker::commit_nacks_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackRepeat {
    /// Delay from a NACK to the next NACK of the same hole.
    pub delay: Duration,
    /// Double the delay with every NACK of a hole: after its n-th NACK the
    /// next is due `delay x 2^(n-1)` later. Used while the RTT is unknown,
    /// so a long path is not flooded with re-requests.
    pub backoff: bool,
    /// Request every NACKed hole once more this long after the NACK (a
    /// copy, see [`MissingTracker::take_due_copies`]); it does not count
    /// as an attempt.
    pub copy_gap: Option<Duration>,
}

impl NackRepeat {
    pub fn fixed(delay: Duration) -> Self {
        Self {
            delay,
            backoff: false,
            copy_gap: None,
        }
    }

    /// The delay after the `nack_count`-th NACK of a hole (1 for the first).
    pub fn after(&self, nack_count: u32) -> Duration {
        if !self.backoff {
            return self.delay;
        }
        self.delay
            .saturating_mul(1 << nack_count.saturating_sub(1).min(16))
    }
}

/// Lifecycle of one tracked hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoleStatus {
    /// Missing and never requested; due at detection + initial delay.
    Fresh,
    /// Missing and scheduled for a NACK at [`HoleInfo::next_nack_at`].
    Scheduled,
    /// Returned by [`MissingTracker::take_due_nacks`] and not yet committed
    /// or deferred.
    Taken,
    /// Missing, but no longer requested (retries exhausted or too late).
    Abandoned,
    /// Arrived; kept only until it reaches the front of the hole queue.
    Recovered,
}

/// A snapshot of one tracked hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoleInfo {
    pub sequence: u32,
    pub status: HoleStatus,
    pub first_missing_at: Instant,
    pub last_nack_at: Option<Instant>,
    pub nack_count: u32,
    /// The next NACK instant of a scheduled hole.
    pub next_nack_at: Option<Instant>,
}

/// The last hole closed by an arrival, for RTT sampling (Karn: use it only
/// when `nack_count == 1` and the arrival was a retransmission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredHole {
    pub sequence: u32,
    pub first_missing_at: Instant,
    /// When the hole's first NACK went out.
    pub first_nack_at: Option<Instant>,
    pub last_nack_at: Option<Instant>,
    pub nack_count: u32,
    pub recovered_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Hole {
    sequence: u32,
    status: HoleStatus,
    nack_count: u32,
    first_missing_at: Instant,
    first_nack_at: Option<Instant>,
    last_nack_at: Option<Instant>,
    next_due: Instant,
    /// When the copy of the last NACK is due, if one is pending.
    copy_at: Option<Instant>,
}

/// Receiver-side loss tracker.
///
/// Holes live in a FIFO in detection order. Holes are only created when the
/// highest sequence advances, so the FIFO is sorted both by (wrapping)
/// sequence and by detection time: expiry pops from the front, and a repair
/// finds its hole by binary search. A heap orders the holes that wait for a
/// repeated (or deferred) NACK; holes that were never requested are taken in
/// FIFO order from a cursor. The cost per packet is O(1) amortised (O(log
/// holes) for a repair), a NACK pass costs O(due · log holes), and an idle
/// check ([`Self::next_nack_at`]) is O(1), independent of the bitrate or the
/// buffer length. Memory follows the actual loss, plus a 4-byte-per-slot
/// ring used only to tell duplicates from late packets.
#[derive(Debug, Clone)]
pub struct MissingTracker {
    seen: Vec<u32>,
    seen_ready: bool,
    capacity: usize,
    highest: Option<u32>,
    recovery_age: Duration,
    initial_delay: Duration,
    holes: VecDeque<Hole>,
    live: usize,
    fresh: usize,
    schedule: BinaryHeap<Reverse<(Instant, u32)>>,
    copies: BinaryHeap<Reverse<(Instant, u32)>>,
    taken: Vec<u32>,
    counters: TrackerCounters,
    last_recovered: Option<RecoveredHole>,
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

    /// `window_packets` sizes the duplicate-detection ring (rounded up to a
    /// power of two, at least 2, at most [`MAX_RECEIVER_WINDOW_PACKETS`]). It
    /// no longer bounds the holes: every hole up to
    /// [`MAX_TRACKED_HOLE_DISTANCE`] behind the highest sequence is tracked.
    /// Nothing is allocated until the first packet is observed.
    pub fn with_limits(window_packets: usize, recovery_age: Duration) -> Self {
        Self {
            seen: Vec::new(),
            seen_ready: false,
            capacity: ring_capacity(window_packets),
            highest: None,
            recovery_age,
            initial_delay: NackSchedule::default().initial_delay,
            holes: VecDeque::new(),
            live: 0,
            fresh: 0,
            schedule: BinaryHeap::new(),
            copies: BinaryHeap::new(),
            taken: Vec::new(),
            counters: TrackerCounters::default(),
            last_recovered: None,
        }
    }

    /// Discards the tracked state (counting open holes as reset) and applies
    /// new limits. Counters are kept.
    pub fn reconfigure(&mut self, window_packets: usize, recovery_age: Duration) {
        self.reset();
        let capacity = ring_capacity(window_packets);
        if capacity != self.capacity {
            self.capacity = capacity;
            self.seen = Vec::new();
        }
        self.recovery_age = recovery_age;
    }

    /// Sets the first-NACK delay used by [`Self::next_nack_at`] until the next
    /// [`Self::take_due_nacks`] call supplies one.
    pub fn set_initial_nack_delay(&mut self, delay: Duration) {
        self.initial_delay = delay;
    }

    pub fn recovery_age(&self) -> Duration {
        self.recovery_age
    }

    pub fn observe_at(&mut self, sequence: u32, now: Instant) -> ReceiverObservation {
        self.ensure_seen(sequence);
        self.expire(now);
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.mark_seen(sequence);
            return observation(sequence, false, false, Vec::new());
        };

        let distance = sequence.wrapping_sub(highest);
        if distance != 0 && distance < (1 << 31) {
            let gap = distance - 1;
            let mut newly_missing = Vec::new();
            if gap > 0 {
                let beyond = gap.saturating_sub(MAX_TRACKED_HOLE_DISTANCE);
                self.counters.holes_unaddressable += u64::from(beyond);
                let first = highest.wrapping_add(1).wrapping_add(beyond);
                let count = gap - beyond;
                // Detection times must stay monotone along the queue.
                let at = self
                    .holes
                    .back()
                    .map_or(now, |hole| hole.first_missing_at.max(now));
                newly_missing.reserve_exact(count as usize);
                self.holes.reserve(count as usize);
                for offset in 0..count {
                    let missing = first.wrapping_add(offset);
                    self.holes.push_back(Hole {
                        sequence: missing,
                        status: HoleStatus::Fresh,
                        nack_count: 0,
                        first_missing_at: at,
                        first_nack_at: None,
                        last_nack_at: None,
                        next_due: at,
                        copy_at: None,
                    });
                    newly_missing.push(missing);
                }
                self.live += count as usize;
                self.counters.holes_opened += u64::from(count);
            }
            self.highest = Some(sequence);
            self.prune_unaddressable(sequence);
            self.mark_seen(sequence);
            return observation(sequence, false, false, newly_missing);
        }

        let behind = highest.wrapping_sub(sequence);
        if behind <= MAX_TRACKED_HOLE_DISTANCE {
            if let Some(index) = self.find_hole(sequence) {
                let hole = &mut self.holes[index];
                if hole.status != HoleStatus::Recovered {
                    hole.status = HoleStatus::Recovered;
                    self.last_recovered = Some(RecoveredHole {
                        sequence,
                        first_missing_at: hole.first_missing_at,
                        first_nack_at: hole.first_nack_at,
                        last_nack_at: hole.last_nack_at,
                        nack_count: hole.nack_count,
                        recovered_at: now,
                    });
                    self.live -= 1;
                    self.counters.holes_recovered += 1;
                    if index == self.fresh {
                        self.advance_fresh();
                    }
                    self.pop_recovered_front();
                    self.mark_seen(sequence);
                    return observation(sequence, false, true, Vec::new());
                }
            }
        }
        if behind as usize >= self.seen.len() {
            // Older than the duplicate-detection ring: as before, refuse it
            // as a duplicate rather than deliver data of unknown status.
            return observation(sequence, true, false, Vec::new());
        }
        let slot = sequence as usize & (self.seen.len() - 1);
        if self.seen[slot] == sequence {
            return observation(sequence, true, false, Vec::new());
        }
        self.counters.late_packets += 1;
        self.seen[slot] = sequence;
        observation(sequence, false, false, Vec::new())
    }

    /// Missing sequences, oldest first.
    pub fn missing_sequences(&self) -> impl Iterator<Item = u32> + '_ {
        self.holes
            .iter()
            .filter(|hole| hole.status != HoleStatus::Recovered)
            .map(|hole| hole.sequence)
    }

    pub fn missing_len(&self) -> usize {
        self.live
    }

    /// Size of the duplicate-detection ring.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn highest(&self) -> Option<u32> {
        self.highest
    }

    pub fn counters(&self) -> TrackerCounters {
        self.counters
    }

    pub fn last_recovered(&self) -> Option<RecoveredHole> {
        self.last_recovered
    }

    pub fn hole(&self, sequence: u32) -> Option<HoleInfo> {
        let hole = self.holes[self.find_hole(sequence)?];
        Some(HoleInfo {
            sequence: hole.sequence,
            status: hole.status,
            first_missing_at: hole.first_missing_at,
            last_nack_at: hole.last_nack_at,
            nack_count: hole.nack_count,
            next_nack_at: matches!(hole.status, HoleStatus::Scheduled).then_some(hole.next_due),
        })
    }

    pub fn reset(&mut self) {
        self.counters.holes_reset += self.live as u64;
        self.holes.clear();
        self.schedule.clear();
        self.copies.clear();
        self.taken.clear();
        self.live = 0;
        self.fresh = 0;
        self.highest = None;
        self.seen_ready = false;
        self.last_recovered = None;
    }

    /// The earliest instant at which [`Self::take_due_nacks`] may return a
    /// sequence, or `None` when no hole waits for a NACK. O(1). It can be
    /// early (a scheduled hole recovered since), never late.
    pub fn next_nack_at(&self) -> Option<Instant> {
        let scheduled = self.schedule.peek().map(|Reverse((due, _))| *due);
        let copy = self.copies.peek().map(|Reverse((due, _))| *due);
        let fresh = self
            .holes
            .get(self.fresh)
            .map(|hole| hole.first_missing_at + self.initial_delay);
        [scheduled, copy, fresh].into_iter().flatten().min()
    }

    /// Appends up to `limit` holes whose NACK copy is due at `now`, oldest
    /// first, and clears them: a copy is sent at most once, whether or not
    /// it reaches the wire, and never changes a hole's NACK count or
    /// schedule. Holes recovered, expired or abandoned since are skipped.
    pub fn take_due_copies(&mut self, now: Instant, limit: usize, out: &mut Vec<u32>) {
        let start = out.len();
        while out.len() - start < limit {
            let Some(&Reverse((due, sequence))) = self.copies.peek() else {
                break;
            };
            if due > now {
                break;
            }
            self.copies.pop();
            let Some(index) = self.find_hole(sequence) else {
                continue;
            };
            let hole = &mut self.holes[index];
            if hole.copy_at != Some(due) {
                continue;
            }
            hole.copy_at = None;
            if matches!(hole.status, HoleStatus::Scheduled | HoleStatus::Taken) {
                out.push(sequence);
            }
        }
        let highest = self.highest.unwrap_or(0);
        out[start..].sort_unstable_by_key(|sequence| Reverse(highest.wrapping_sub(*sequence)));
    }

    /// The instant at which the oldest open hole expires.
    pub fn next_expiry_at(&self) -> Option<Instant> {
        self.holes
            .iter()
            .find(|hole| hole.status != HoleStatus::Recovered)
            .map(|hole| hole.first_missing_at + self.recovery_age)
    }

    /// Appends up to `limit` holes that are due for a NACK at `now` to `out`,
    /// oldest first. Nothing is marked as requested here: the caller passes
    /// every returned sequence either to [`Self::commit_nacks`] (it was put on
    /// the wire) or to [`Self::defer_nacks`]. Holes taken and neither
    /// committed nor deferred are due again at the next call.
    pub fn take_due_nacks(
        &mut self,
        now: Instant,
        schedule: &NackSchedule,
        limit: usize,
        out: &mut Vec<u32>,
    ) {
        self.initial_delay = schedule.initial_delay;
        self.expire(now);
        self.restore_taken(now);
        let start = out.len();

        while out.len() - start < limit {
            let Some(&Reverse((due, sequence))) = self.schedule.peek() else {
                break;
            };
            if due > now {
                break;
            }
            self.schedule.pop();
            let Some(index) = self.find_hole(sequence) else {
                continue;
            };
            let recovery_age = self.recovery_age;
            let hole = &mut self.holes[index];
            if hole.status != HoleStatus::Scheduled || hole.next_due != due {
                continue;
            }
            if hole.nack_count >= schedule.max_retries {
                hole.status = HoleStatus::Abandoned;
                self.counters.retries_exhausted += 1;
                continue;
            }
            if too_late(hole, now, recovery_age, schedule.min_time_left) {
                hole.status = HoleStatus::Abandoned;
                self.counters.nack_too_late += 1;
                continue;
            }
            hole.status = HoleStatus::Taken;
            self.taken.push(sequence);
            out.push(sequence);
        }

        let mut index = self.fresh;
        while out.len() - start < limit && index < self.holes.len() {
            let recovery_age = self.recovery_age;
            let hole = &mut self.holes[index];
            index += 1;
            if hole.status != HoleStatus::Fresh {
                continue;
            }
            if hole.first_missing_at + schedule.initial_delay > now {
                break;
            }
            if hole.nack_count >= schedule.max_retries {
                hole.status = HoleStatus::Abandoned;
                self.counters.retries_exhausted += 1;
                continue;
            }
            if too_late(hole, now, recovery_age, schedule.min_time_left) {
                hole.status = HoleStatus::Abandoned;
                self.counters.nack_too_late += 1;
                continue;
            }
            out.push(hole.sequence);
        }
        self.advance_fresh();

        let highest = self.highest.unwrap_or(0);
        out[start..].sort_unstable_by_key(|sequence| Reverse(highest.wrapping_sub(*sequence)));
    }

    /// Records that NACKs for `sent` went on the wire at `now`; the next NACK
    /// of each is due at `now + repeat_delay`.
    pub fn commit_nacks(&mut self, sent: &[u32], now: Instant, repeat_delay: Duration) {
        self.commit_nacks_with(sent, now, NackRepeat::fixed(repeat_delay));
    }

    /// [`Self::commit_nacks`] with a per-hole repeat policy (backoff while
    /// the RTT is unknown).
    pub fn commit_nacks_with(&mut self, sent: &[u32], now: Instant, repeat: NackRepeat) {
        for &sequence in sent {
            let Some(index) = self.find_hole(sequence) else {
                continue;
            };
            let hole = &mut self.holes[index];
            if matches!(hole.status, HoleStatus::Recovered | HoleStatus::Abandoned) {
                continue;
            }
            hole.nack_count = hole.nack_count.saturating_add(1);
            hole.first_nack_at.get_or_insert(now);
            hole.last_nack_at = Some(now);
            if let Some(gap) = repeat.copy_gap {
                let copy_at = now + gap;
                hole.copy_at = Some(copy_at);
                self.copies.push(Reverse((copy_at, sequence)));
            }
            let next_due = now + repeat.after(hole.nack_count);
            hole.next_due = next_due;
            hole.status = HoleStatus::Scheduled;
            self.schedule.push(Reverse((next_due, sequence)));
        }
        self.advance_fresh();
    }

    /// Keeps `unsent` holes due, but not before `at` (for example when the
    /// return bandwidth refused their NACK). Their NACK count is unchanged.
    pub fn defer_nacks(&mut self, unsent: &[u32], at: Instant) {
        for &sequence in unsent {
            let Some(index) = self.find_hole(sequence) else {
                continue;
            };
            let hole = &mut self.holes[index];
            if matches!(hole.status, HoleStatus::Recovered | HoleStatus::Abandoned) {
                continue;
            }
            hole.next_due = at;
            hole.status = HoleStatus::Scheduled;
            self.schedule.push(Reverse((at, sequence)));
        }
        self.advance_fresh();
    }

    /// Compatibility wrapper: selects every due hole, marks it as requested
    /// at `now`, and returns the sequences newest first (the historical
    /// order). `min_retries` is accepted for source compatibility; as before,
    /// a hole is requested until it expires or reaches `max_retries`.
    pub fn nacks_due(
        &mut self,
        now: Instant,
        initial_delay: Duration,
        repeat_delay: Duration,
        _min_retries: u32,
        max_retries: u32,
    ) -> Vec<u32> {
        let schedule = NackSchedule {
            initial_delay,
            repeat_delay,
            max_retries,
            min_time_left: Duration::ZERO,
        };
        let mut due = Vec::new();
        self.take_due_nacks(now, &schedule, usize::MAX, &mut due);
        self.commit_nacks(&due, now, repeat_delay);
        due.reverse();
        due
    }

    fn ensure_seen(&mut self, first: u32) {
        if self.seen_ready {
            return;
        }
        let mask = self.capacity - 1;
        if self.seen.len() != self.capacity {
            self.seen = vec![0; self.capacity];
        }
        // Vacant tags map to their own slot but lie about 2^31 away from the
        // first sequence, so they cannot match a real arrival.
        let far = (first ^ 0x8000_0000) & !(mask as u32);
        for (index, tag) in self.seen.iter_mut().enumerate() {
            *tag = far | index as u32;
        }
        self.seen_ready = true;
    }

    fn mark_seen(&mut self, sequence: u32) {
        let mask = self.seen.len() - 1;
        self.seen[sequence as usize & mask] = sequence;
    }

    fn find_hole(&self, sequence: u32) -> Option<usize> {
        let base = self.holes.front()?.sequence;
        let key = sequence.wrapping_sub(base);
        let last = self.holes.back()?.sequence.wrapping_sub(base);
        if key > last {
            return None;
        }
        self.holes
            .binary_search_by_key(&key, |hole| hole.sequence.wrapping_sub(base))
            .ok()
    }

    fn expire(&mut self, now: Instant) {
        while let Some(front) = self.holes.front() {
            if front.status != HoleStatus::Recovered {
                if now.saturating_duration_since(front.first_missing_at) < self.recovery_age {
                    break;
                }
                self.live -= 1;
                self.counters.holes_expired += 1;
            }
            self.pop_front_hole();
        }
        self.advance_fresh();
    }

    fn prune_unaddressable(&mut self, highest: u32) {
        while let Some(front) = self.holes.front() {
            if highest.wrapping_sub(front.sequence) <= MAX_TRACKED_HOLE_DISTANCE {
                break;
            }
            if front.status != HoleStatus::Recovered {
                self.live -= 1;
                self.counters.holes_unaddressable += 1;
            }
            self.pop_front_hole();
        }
        self.advance_fresh();
    }

    fn pop_recovered_front(&mut self) {
        while self
            .holes
            .front()
            .is_some_and(|hole| hole.status == HoleStatus::Recovered)
        {
            self.pop_front_hole();
        }
        self.advance_fresh();
    }

    fn pop_front_hole(&mut self) {
        self.holes.pop_front();
        self.fresh = self.fresh.saturating_sub(1);
    }

    fn advance_fresh(&mut self) {
        while self
            .holes
            .get(self.fresh)
            .is_some_and(|hole| hole.status != HoleStatus::Fresh)
        {
            self.fresh += 1;
        }
    }

    /// Holes taken by an earlier pass and never committed or deferred are due
    /// again now, so a caller mistake cannot lose a hole.
    fn restore_taken(&mut self, now: Instant) {
        if self.taken.is_empty() {
            return;
        }
        let taken = std::mem::take(&mut self.taken);
        for &sequence in &taken {
            let Some(index) = self.find_hole(sequence) else {
                continue;
            };
            let hole = &mut self.holes[index];
            if hole.status == HoleStatus::Taken {
                hole.status = HoleStatus::Scheduled;
                hole.next_due = now;
                self.schedule.push(Reverse((now, sequence)));
            }
        }
        self.taken = taken;
        self.taken.clear();
    }
}

#[cfg(test)]
impl MissingTracker {
    /// Structural invariants, checked by the tests after each operation.
    fn check_invariants(&self) {
        let live = self
            .holes
            .iter()
            .filter(|hole| hole.status != HoleStatus::Recovered)
            .count();
        assert_eq!(live, self.live, "live hole count");
        if let Some(front) = self.holes.front() {
            let base = front.sequence;
            for pair in self.holes.iter().collect::<Vec<_>>().windows(2) {
                assert!(
                    pair[0].sequence.wrapping_sub(base) < pair[1].sequence.wrapping_sub(base),
                    "holes ascend"
                );
                assert!(pair[0].first_missing_at <= pair[1].first_missing_at);
            }
            let highest = self.highest.expect("holes imply a highest sequence");
            assert!(highest.wrapping_sub(base) <= MAX_TRACKED_HOLE_DISTANCE);
            assert_ne!(
                front.status,
                HoleStatus::Recovered,
                "front tombstones are popped"
            );
        }
        for (index, hole) in self.holes.iter().enumerate() {
            if index < self.fresh {
                assert_ne!(
                    hole.status,
                    HoleStatus::Fresh,
                    "fresh cursor skipped a hole"
                );
            }
            if hole.status == HoleStatus::Scheduled {
                assert!(
                    self.schedule
                        .iter()
                        .any(|Reverse((due, sequence))| *sequence == hole.sequence
                            && *due == hole.next_due),
                    "scheduled hole {} has a heap entry",
                    hole.sequence
                );
            }
        }
        if let Some(hole) = self.holes.get(self.fresh) {
            assert_eq!(hole.status, HoleStatus::Fresh);
        }
    }
}

fn observation(
    sequence: u32,
    duplicate: bool,
    recovered: bool,
    newly_missing: Vec<u32>,
) -> ReceiverObservation {
    ReceiverObservation {
        sequence,
        duplicate,
        recovered,
        newly_missing,
    }
}

fn ring_capacity(window_packets: usize) -> usize {
    window_packets
        .clamp(2, MAX_RECEIVER_WINDOW_PACKETS)
        .next_power_of_two()
}

fn too_late(hole: &Hole, now: Instant, recovery_age: Duration, min_time_left: Duration) -> bool {
    !min_time_left.is_zero()
        && (hole.first_missing_at + recovery_age).saturating_duration_since(now) < min_time_left
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
        // Every hole a 16-bit NACK can still address is tracked, whatever the
        // ring size; the rest of the gap is counted, not dropped silently.
        let tracked = MAX_TRACKED_HOLE_DISTANCE as usize;
        assert_eq!(observation.newly_missing.len(), tracked);
        assert_eq!(observation.newly_missing[0], 1_000_000 - tracked as u32);
        assert_eq!(*observation.newly_missing.last().unwrap(), 999_999);
        assert_eq!(tracker.capacity(), 8);
        assert_eq!(tracker.missing_len(), tracked);
        assert_eq!(
            tracker.counters().holes_unaddressable,
            999_989 - tracked as u64
        );
        tracker.check_invariants();

        tracker.observe_at(1_000_001, start + Duration::from_millis(101));
        assert_eq!(tracker.missing_len(), 0);
        assert_eq!(tracker.counters().holes_expired, tracked as u64);
        tracker.check_invariants();
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

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn sequences(payloads: &[ReceivedPayload]) -> Vec<u32> {
        payloads.iter().map(|payload| payload.sequence).collect()
    }

    #[test]
    fn ordered_in_order_packets_take_the_fast_path() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_deadline(4, Duration::from_millis(10));
        let mut out = Vec::new();
        for sequence in 100..110 {
            assert_eq!(
                buffer.push_into(payload(sequence, 0), start, &mut out),
                Ok(OrderedPush::Released)
            );
            assert_eq!(buffer.pending_len(), 0);
        }
        assert_eq!(sequences(&out), (100..110).collect::<Vec<_>>());
        assert_eq!(buffer.stats().released, 10);
        assert_eq!(buffer.stats().held_max, 0);
        assert_eq!(buffer.next_deadline(), None);
    }

    #[test]
    fn ordered_late_packet_after_skip_is_dropped_not_held() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(8, Duration::from_millis(10));
        buffer.push_at(payload(1, 1), start).unwrap();
        assert!(buffer.push_at(payload(3, 3), start).unwrap().is_empty());
        assert_eq!(sequences(&buffer.release_expired(start + ms(10))), vec![3]);
        assert_eq!(buffer.pending_len(), 0);
        assert_eq!(buffer.skipped_packets(), 1);
        assert_eq!(buffer.gaps_skipped(), 1);

        // The repair of 2 comes after its gap was given up.
        let mut out = Vec::new();
        assert_eq!(
            buffer.push_into(payload(2, 2), start + ms(11), &mut out),
            Ok(OrderedPush::Late)
        );
        assert!(out.is_empty());
        assert_eq!(buffer.pending_len(), 0);
        assert_eq!(buffer.late_dropped(), 1);
        assert_eq!(buffer.next_sequence(), Some(4));
        // A copy of a released packet is late as well.
        assert!(buffer
            .push_at(payload(1, 1), start + ms(12))
            .unwrap()
            .is_empty());
        assert_eq!(buffer.late_dropped(), 2);
        assert_eq!(buffer.pending_len(), 0);
    }

    #[test]
    fn ordered_two_expired_gaps_release_in_one_call() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(16, Duration::from_millis(10));
        buffer.push_at(payload(10, 0), start).unwrap();
        // Gaps at 11 and 14.
        assert!(buffer.push_at(payload(12, 0), start).unwrap().is_empty());
        assert!(buffer
            .push_at(payload(13, 0), start + ms(1))
            .unwrap()
            .is_empty());
        assert!(buffer
            .push_at(payload(15, 0), start + ms(2))
            .unwrap()
            .is_empty());
        assert_eq!(buffer.next_deadline(), Some(start + ms(10)));
        assert!(buffer.release_expired(start + ms(9)).is_empty());
        assert_eq!(
            sequences(&buffer.release_expired(start + ms(12))),
            vec![12, 13, 15]
        );
        assert_eq!(buffer.gaps_skipped(), 2);
        assert_eq!(buffer.skipped_packets(), 2);
        assert_eq!(buffer.pending_len(), 0);
        assert_eq!(buffer.next_sequence(), Some(16));
    }

    #[test]
    fn ordered_gap_deadline_counts_from_its_first_successor() {
        // 11 is missing; 13 arrives first, then 12 (a repair or reordering)
        // later: the gap at 11 has been open since 13 arrived.
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(8, Duration::from_millis(10));
        buffer.push_at(payload(10, 0), start).unwrap();
        assert!(buffer.push_at(payload(13, 0), start).unwrap().is_empty());
        assert!(buffer
            .push_at(payload(12, 0), start + ms(8))
            .unwrap()
            .is_empty());
        assert_eq!(buffer.next_deadline(), Some(start + ms(10)));
        assert_eq!(
            sequences(&buffer.release_expired(start + ms(10))),
            vec![12, 13]
        );
    }

    #[test]
    fn ordered_keys_cross_the_u32_rollover() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(8, Duration::from_millis(10));
        buffer.push_at(payload(u32::MAX - 1, 0), start).unwrap();
        assert!(buffer.push_at(payload(1, 0), start).unwrap().is_empty());
        assert!(buffer.push_at(payload(0, 0), start).unwrap().is_empty());
        assert_eq!(
            sequences(&buffer.push_at(payload(u32::MAX, 0), start).unwrap()),
            vec![u32::MAX, 0, 1]
        );
        assert_eq!(buffer.next_sequence(), Some(2));
        // Behind the first packet, across the boundary of the first
        // extension: late, not held.
        let mut fresh = OrderedPayloadBuffer::new(8);
        fresh.push_at(payload(0, 0), start).unwrap();
        assert!(fresh
            .push_at(payload(u32::MAX, 0), start)
            .unwrap()
            .is_empty());
        assert_eq!(fresh.late_dropped(), 1);
        assert_eq!(fresh.pending_len(), 0);
    }

    #[test]
    fn ordered_overflow_with_an_expired_gap_releases_instead_of_failing() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_reorder_delay(2, Duration::from_millis(10));
        buffer.push_at(payload(30, 0), start).unwrap();
        assert!(buffer.push_at(payload(32, 0), start).unwrap().is_empty());
        assert!(buffer.push_at(payload(33, 0), start).unwrap().is_empty());
        // The bound trips at 34, but the gap at 31 is due by then.
        assert_eq!(
            sequences(&buffer.push_at(payload(34, 0), start + ms(10)).unwrap()),
            vec![32, 33, 34]
        );
        assert_eq!(buffer.skipped_packets(), 1);
    }

    #[test]
    fn ordered_with_deadline_skips_the_oldest_gap_at_its_bound() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::with_deadline(2, Duration::from_secs(1));
        assert_eq!(buffer.overflow_policy(), OverflowPolicy::SkipOldestGap);
        buffer.push_at(payload(30, 0), start).unwrap();
        assert!(buffer.push_at(payload(32, 0), start).unwrap().is_empty());
        assert!(buffer.push_at(payload(34, 0), start).unwrap().is_empty());
        // Three held: the gap at 31 goes, 32 is released; 33 still waits.
        assert_eq!(
            sequences(&buffer.push_at(payload(35, 0), start).unwrap()),
            vec![32]
        );
        assert_eq!(buffer.pending_len(), 2);
        assert_eq!(buffer.gaps_skipped(), 1);
        for sequence in 36..1_000 {
            buffer.push_at(payload(sequence, 0), start).unwrap();
            assert!(buffer.pending_len() <= 2);
        }
        assert_eq!(buffer.skipped_packets(), 2);
    }

    #[test]
    fn ordered_flush_all_releases_in_order() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::new(8);
        buffer.push_at(payload(1, 0), start).unwrap();
        for sequence in [5, 3, 4, 8] {
            assert!(buffer
                .push_at(payload(sequence, 0), start)
                .unwrap()
                .is_empty());
        }
        assert_eq!(buffer.next_deadline(), None);
        assert_eq!(sequences(&buffer.flush_all()), vec![3, 4, 5, 8]);
        assert_eq!(buffer.skipped_packets(), 3);
        assert_eq!(buffer.gaps_skipped(), 2);
        assert_eq!(buffer.pending_len(), 0);
        assert_eq!(buffer.next_sequence(), Some(9));
    }

    #[test]
    fn ordered_duplicates_are_counted_and_dropped() {
        let start = Instant::now();
        let mut buffer = OrderedPayloadBuffer::new(8);
        buffer.push_at(payload(1, 0), start).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            buffer.push_into(payload(3, 0), start, &mut out),
            Ok(OrderedPush::Held)
        );
        assert_eq!(
            buffer.push_into(payload(3, 0), start, &mut out),
            Ok(OrderedPush::Duplicate)
        );
        let mut flagged = payload(2, 0);
        flagged.duplicate = true;
        assert_eq!(
            buffer.push_into(flagged, start, &mut out),
            Ok(OrderedPush::Duplicate)
        );
        assert_eq!(buffer.stats().duplicates, 2);
        assert!(out.is_empty());
    }

    /// Every payload the buffer accepts comes out once, in strictly
    /// increasing extended order, and the skipped count fills the gaps.
    #[test]
    fn ordered_random_streams_keep_the_invariants() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..20u32 {
            let start = Instant::now();
            let mut buffer = if round % 2 == 0 {
                OrderedPayloadBuffer::with_deadline(64, Duration::from_millis(20))
            } else {
                OrderedPayloadBuffer::with_reorder_delay(4_096, Duration::from_millis(20))
            };
            let base = u32::MAX - 500 + round * 7;
            let mut out = Vec::new();
            let mut accepted = 0u64;
            let mut late = 0u64;
            let mut repairs: Vec<(u64, u32)> = Vec::new();
            for step in 0..3_000u64 {
                let now = start + Duration::from_micros(step * 100);
                let sequence = base.wrapping_add(step as u32);
                let roll = rand() % 100;
                if roll < 5 {
                    // Lost; repaired 2-40 ms later, or never.
                    if rand() % 4 != 0 {
                        repairs.push((step + 20 + rand() % 380, sequence));
                    }
                } else {
                    match buffer.push_into(payload(sequence, 0), now, &mut out) {
                        Ok(OrderedPush::Released | OrderedPush::Held) => accepted += 1,
                        Ok(OrderedPush::Late) => late += 1,
                        Ok(OrderedPush::Duplicate) => {}
                        Err(error) => panic!("{error}"),
                    }
                }
                repairs.sort_unstable();
                while repairs.first().is_some_and(|&(due, _)| due <= step) {
                    let (_, repaired) = repairs.remove(0);
                    match buffer.push_into(payload(repaired, 0), now, &mut out) {
                        Ok(OrderedPush::Released | OrderedPush::Held) => accepted += 1,
                        Ok(OrderedPush::Late) => late += 1,
                        Ok(OrderedPush::Duplicate) => {}
                        Err(error) => panic!("{error}"),
                    }
                }
                if step % 10 == 0 {
                    buffer.release_expired_into(now, &mut out);
                }
            }
            buffer.flush_all_into(&mut out);
            let stats = buffer.stats();
            assert_eq!(out.len() as u64, accepted);
            assert_eq!(stats.released, accepted);
            assert_eq!(stats.late_dropped, late);
            let first = u64::from(out[0].sequence);
            let mut previous = first;
            for released in &out[1..] {
                let distance = released.sequence.wrapping_sub(previous as u32);
                assert!((1..1 << 31).contains(&distance));
                previous += u64::from(distance);
            }
            assert_eq!(
                previous - first + 1,
                out.len() as u64 + stats.packets_skipped
            );
        }
    }

    fn schedule(initial: u64, max_retries: u32) -> NackSchedule {
        NackSchedule {
            initial_delay: ms(initial),
            repeat_delay: ms(20),
            max_retries,
            min_time_left: Duration::ZERO,
        }
    }

    fn take(
        tracker: &mut MissingTracker,
        now: Instant,
        plan: &NackSchedule,
        limit: usize,
    ) -> Vec<u32> {
        let mut out = Vec::new();
        tracker.take_due_nacks(now, plan, limit, &mut out);
        tracker.check_invariants();
        out
    }

    #[test]
    fn backoff_doubles_the_repeat_delay_per_attempt() {
        let repeat = NackRepeat {
            delay: ms(5),
            backoff: true,
            copy_gap: None,
        };
        assert_eq!(repeat.after(1), ms(5));
        assert_eq!(repeat.after(2), ms(10));
        assert_eq!(repeat.after(4), ms(40));
        assert_eq!(NackRepeat::fixed(ms(5)).after(4), ms(5));

        let t0 = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(10));
        tracker.observe_at(0, t0);
        tracker.observe_at(2, t0);
        let plan = schedule(0, 20);
        let mut at = t0;
        let mut gaps = Vec::new();
        for _ in 0..4 {
            assert_eq!(take(&mut tracker, at, &plan, 8), vec![1]);
            tracker.commit_nacks_with(&[1], at, repeat);
            tracker.check_invariants();
            let next = tracker.next_nack_at().unwrap();
            gaps.push(next - at);
            at = next;
        }
        assert_eq!(gaps, vec![ms(5), ms(10), ms(20), ms(40)]);
    }

    #[test]
    fn nack_copies_are_due_once_and_do_not_count_as_attempts() {
        let t0 = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(10));
        tracker.observe_at(0, t0);
        tracker.observe_at(3, t0);
        let plan = schedule(0, 20);
        assert_eq!(take(&mut tracker, t0, &plan, 8), vec![1, 2]);
        let repeat = NackRepeat {
            delay: ms(20),
            backoff: false,
            copy_gap: Some(ms(2)),
        };
        tracker.commit_nacks_with(&[1, 2], t0, repeat);
        assert_eq!(tracker.next_nack_at(), Some(t0 + ms(2)));
        let mut copies = Vec::new();
        tracker.take_due_copies(t0 + ms(1), 8, &mut copies);
        assert!(copies.is_empty());
        // Hole 2 is recovered before its copy is due: only 1 is copied.
        tracker.observe_at(2, t0 + ms(1));
        tracker.take_due_copies(t0 + ms(2), 8, &mut copies);
        assert_eq!(copies, vec![1]);
        tracker.check_invariants();
        assert_eq!(tracker.hole(1).unwrap().nack_count, 1);
        assert_eq!(tracker.hole(1).unwrap().next_nack_at, Some(t0 + ms(20)));
        copies.clear();
        tracker.take_due_copies(t0 + ms(3), 8, &mut copies);
        assert!(copies.is_empty(), "a copy is sent once");
        assert_eq!(tracker.next_nack_at(), Some(t0 + ms(20)));
    }

    #[test]
    fn tracker_allocates_nothing_until_the_first_packet() {
        let mut tracker = MissingTracker::with_limits(1 << 20, Duration::from_secs(1));
        assert_eq!(tracker.capacity(), 1 << 20);
        assert!(tracker.seen.is_empty());
        tracker.observe_at(5, Instant::now());
        assert_eq!(tracker.seen.len(), 1 << 20);
    }

    #[test]
    fn a_burst_larger_than_the_ring_keeps_every_hole() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(8, Duration::from_secs(1));
        tracker.observe_at(10, start);
        assert_eq!(
            tracker.observe_at(30, start).newly_missing,
            (11..30).collect::<Vec<_>>()
        );
        assert_eq!(
            tracker.observe_at(40, start).newly_missing,
            (31..40).collect::<Vec<_>>()
        );
        assert_eq!(tracker.missing_len(), 28);
        // Slot collisions (11 and 19 share a slot of the 8-entry ring) no
        // longer drop holes.
        assert!(tracker.observe_at(11, start).recovered);
        assert!(tracker.observe_at(19, start).recovered);
        assert!(tracker.observe_at(35, start).recovered);
        assert_eq!(tracker.missing_len(), 25);
        assert_eq!(
            tracker.missing_sequences().collect::<Vec<_>>(),
            (12..19)
                .chain(20..30)
                .chain(31..35)
                .chain(36..40)
                .collect::<Vec<_>>()
        );
        assert_eq!(tracker.counters().holes_opened, 28);
        assert_eq!(tracker.counters().holes_recovered, 3);
        tracker.check_invariants();
    }

    #[test]
    fn a_full_16_bit_gap_is_tracked_and_the_horizon_is_counted() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(1024, Duration::from_secs(1));
        tracker.observe_at(0, start);
        let observation = tracker.observe_at(MAX_TRACKED_HOLE_DISTANCE + 1, start);
        assert_eq!(
            observation.newly_missing.len(),
            MAX_TRACKED_HOLE_DISTANCE as usize
        );
        assert_eq!(tracker.counters().holes_unaddressable, 0);
        // The next packet pushes the oldest hole past the 16-bit horizon.
        tracker.observe_at(MAX_TRACKED_HOLE_DISTANCE + 2, start);
        assert_eq!(tracker.counters().holes_unaddressable, 1);
        assert_eq!(
            tracker.missing_len(),
            MAX_TRACKED_HOLE_DISTANCE as usize - 1
        );
        assert_eq!(tracker.missing_sequences().next(), Some(2));
        // A repair for the far end of the horizon is still recognised.
        assert!(tracker.observe_at(2, start).recovered);
        tracker.check_invariants();
    }

    #[test]
    fn a_late_packet_after_expiry_is_neither_duplicate_nor_recovered() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, ms(100));
        tracker.observe_at(1, start);
        assert_eq!(tracker.observe_at(3, start).newly_missing, vec![2]);
        tracker.observe_at(4, start + ms(101));
        assert_eq!(tracker.missing_len(), 0);
        assert_eq!(tracker.counters().holes_expired, 1);

        let late = tracker.observe_at(2, start + ms(102));
        assert!(!late.duplicate);
        assert!(!late.recovered);
        assert_eq!(tracker.counters().late_packets, 1);
        assert!(tracker.observe_at(2, start + ms(103)).duplicate);
        assert!(tracker.observe_at(4, start + ms(103)).duplicate);
        tracker.check_invariants();
    }

    #[test]
    fn take_due_nacks_is_oldest_first_and_respects_the_limit() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(4096, Duration::from_secs(1));
        // 1000 isolated holes: 1, 3, 5, ..., 1999.
        for sequence in (0..=2000).step_by(2) {
            tracker.observe_at(sequence, start);
        }
        assert_eq!(tracker.missing_len(), 1000);
        let plan = schedule(15, 20);
        assert!(take(&mut tracker, start + ms(14), &plan, 200).is_empty());

        let now = start + ms(15);
        let mut all = Vec::new();
        for _ in 0..5 {
            let batch = take(&mut tracker, now, &plan, 200);
            assert_eq!(batch.len(), 200);
            assert!(batch.windows(2).all(|pair| pair[0] < pair[1]));
            if let Some(&last) = all.last() {
                assert!(batch[0] > last);
            }
            tracker.commit_nacks(&batch, now, ms(20));
            tracker.check_invariants();
            all.extend(batch);
        }
        assert_eq!(all, (1..2000).step_by(2).collect::<Vec<_>>());
        assert!(take(&mut tracker, now, &plan, 200).is_empty());
    }

    #[test]
    fn only_committed_holes_count_as_requested() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(0, start);
        tracker.observe_at(11, start);
        let plan = schedule(0, 20);
        let due = take(&mut tracker, start, &plan, usize::MAX);
        assert_eq!(due, (1..11).collect::<Vec<_>>());

        tracker.commit_nacks(&due[..4], start, ms(20));
        tracker.check_invariants();
        for sequence in 1..5 {
            let hole = tracker.hole(sequence).unwrap();
            assert_eq!(hole.nack_count, 1);
            assert_eq!(hole.last_nack_at, Some(start));
            assert_eq!(hole.next_nack_at, Some(start + ms(20)));
        }
        for sequence in 5..11 {
            let hole = tracker.hole(sequence).unwrap();
            assert_eq!(hole.nack_count, 0);
            assert_eq!(hole.status, HoleStatus::Fresh);
        }
        // Not committed: still due, at the same instant.
        assert_eq!(
            take(&mut tracker, start, &plan, usize::MAX),
            (5..11).collect::<Vec<_>>()
        );
    }

    #[test]
    fn deferred_holes_stay_due_from_the_deferral_instant() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(0, start);
        tracker.observe_at(4, start);
        let plan = schedule(15, 20);
        let now = start + ms(15);
        let due = take(&mut tracker, now, &plan, usize::MAX);
        assert_eq!(due, vec![1, 2, 3]);
        tracker.defer_nacks(&due, now + ms(100));
        tracker.check_invariants();
        assert_eq!(tracker.next_nack_at(), Some(now + ms(100)));
        assert!(take(&mut tracker, now + ms(99), &plan, usize::MAX).is_empty());
        assert_eq!(
            take(&mut tracker, now + ms(100), &plan, usize::MAX),
            vec![1, 2, 3]
        );
        assert_eq!(tracker.hole(2).unwrap().nack_count, 0);
    }

    #[test]
    fn taken_holes_that_are_neither_committed_nor_deferred_come_back() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(0, start);
        tracker.observe_at(2, start);
        let plan = schedule(0, 20);
        let due = take(&mut tracker, start, &plan, usize::MAX);
        tracker.commit_nacks(&due, start, ms(20));
        let later = start + ms(20);
        assert_eq!(take(&mut tracker, later, &plan, usize::MAX), vec![1]);
        assert_eq!(tracker.hole(1).unwrap().status, HoleStatus::Taken);
        // The caller dropped the batch: the hole is due again.
        assert_eq!(take(&mut tracker, later, &plan, usize::MAX), vec![1]);
        assert_eq!(tracker.hole(1).unwrap().nack_count, 1);
    }

    #[test]
    fn repeats_follow_the_commit_time_delay_and_stop_at_max_retries() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(0, start);
        tracker.observe_at(2, start);
        let plan = schedule(15, 2);
        assert_eq!(tracker.next_nack_at(), Some(start + ms(15)));

        let first = start + ms(15);
        assert_eq!(take(&mut tracker, first, &plan, usize::MAX), vec![1]);
        tracker.commit_nacks(&[1], first, ms(30));
        assert_eq!(tracker.next_nack_at(), Some(first + ms(30)));
        assert!(take(&mut tracker, first + ms(29), &plan, usize::MAX).is_empty());

        let second = first + ms(30);
        assert_eq!(take(&mut tracker, second, &plan, usize::MAX), vec![1]);
        tracker.commit_nacks(&[1], second, ms(10));
        assert_eq!(tracker.hole(1).unwrap().nack_count, 2);
        assert_eq!(tracker.hole(1).unwrap().last_nack_at, Some(second));

        assert!(take(&mut tracker, second + ms(10), &plan, usize::MAX).is_empty());
        assert_eq!(tracker.counters().retries_exhausted, 1);
        assert_eq!(tracker.hole(1).unwrap().status, HoleStatus::Abandoned);
        assert_eq!(tracker.missing_len(), 1);
        assert_eq!(tracker.next_nack_at(), None);

        // An abandoned hole can still be repaired, and the repair reports
        // what an RTT estimator needs.
        let arrival = tracker.observe_at(1, second + ms(12));
        assert!(arrival.recovered);
        assert_eq!(
            tracker.last_recovered(),
            Some(RecoveredHole {
                sequence: 1,
                first_missing_at: start,
                first_nack_at: Some(start + ms(15)),
                last_nack_at: Some(second),
                nack_count: 2,
                recovered_at: second + ms(12),
            })
        );
        tracker.check_invariants();
    }

    #[test]
    fn holes_too_close_to_their_deadline_are_skipped_and_counted() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, ms(100));
        tracker.observe_at(0, start);
        tracker.observe_at(2, start);
        tracker.observe_at(4, start + ms(40));
        let plan = NackSchedule {
            min_time_left: ms(50),
            ..schedule(15, 20)
        };
        // Hole 1 was detected at +0 (deadline +100) and hole 3 at +40
        // (deadline +140): at +60 only hole 3 has 50 ms left.
        assert_eq!(
            take(&mut tracker, start + ms(60), &plan, usize::MAX),
            vec![3]
        );
        assert_eq!(tracker.counters().nack_too_late, 1);
        assert_eq!(tracker.hole(1).unwrap().status, HoleStatus::Abandoned);
        assert_eq!(tracker.missing_len(), 2);
        assert!(tracker.observe_at(1, start + ms(61)).recovered);
    }

    #[test]
    fn next_nack_at_is_idle_or_in_the_future_after_a_pass() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.set_initial_nack_delay(ms(15));
        assert_eq!(tracker.next_nack_at(), None);
        tracker.observe_at(0, start);
        tracker.observe_at(1, start);
        assert_eq!(tracker.next_nack_at(), None);
        tracker.observe_at(5, start + ms(3));
        assert_eq!(tracker.next_nack_at(), Some(start + ms(18)));
        let now = start + ms(18);
        let due = take(&mut tracker, now, &schedule(15, 20), usize::MAX);
        tracker.commit_nacks(&due, now, ms(20));
        assert!(tracker.next_nack_at().unwrap() > now);
        for sequence in 2..5 {
            tracker.observe_at(sequence, now + ms(1));
        }
        // The stale heap entries may make the hint early, never late; one
        // pass clears them.
        assert!(take(&mut tracker, now + ms(20), &schedule(15, 20), usize::MAX).is_empty());
        assert_eq!(tracker.next_nack_at(), None);
    }

    #[test]
    fn holes_and_schedule_cross_the_u32_rollover() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(16, Duration::from_secs(1));
        tracker.observe_at(u32::MAX - 3, start);
        assert_eq!(
            tracker.observe_at(2, start).newly_missing,
            vec![u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 1]
        );
        let plan = schedule(0, 20);
        let due = take(&mut tracker, start, &plan, 3);
        assert_eq!(due, vec![u32::MAX - 2, u32::MAX - 1, u32::MAX]);
        tracker.commit_nacks(&due, start, ms(20));
        assert_eq!(take(&mut tracker, start, &plan, 3), vec![0, 1]);
        tracker.commit_nacks(&[0, 1], start, ms(20));
        assert!(tracker.observe_at(u32::MAX, start).recovered);
        assert!(tracker.observe_at(0, start).recovered);
        assert_eq!(
            take(&mut tracker, start + ms(20), &plan, usize::MAX),
            vec![u32::MAX - 2, u32::MAX - 1, 1]
        );
        assert!(tracker.observe_at(0, start).duplicate);
        tracker.check_invariants();
    }

    #[test]
    fn nacks_due_wrapper_keeps_its_historical_contract() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(0, start);
        tracker.observe_at(4, start);
        assert!(tracker
            .nacks_due(start + ms(14), ms(15), ms(20), 6, 20)
            .is_empty());
        let now = start + ms(15);
        assert_eq!(tracker.nacks_due(now, ms(15), ms(20), 6, 20), vec![3, 2, 1]);
        assert!(tracker
            .nacks_due(now + ms(19), ms(15), ms(20), 6, 20)
            .is_empty());
        assert_eq!(
            tracker.nacks_due(now + ms(20), ms(15), ms(20), 6, 20),
            vec![3, 2, 1]
        );
        assert_eq!(tracker.hole(1).unwrap().nack_count, 2);
    }

    #[test]
    fn reset_and_reconfigure_count_discarded_holes() {
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(64, Duration::from_secs(1));
        tracker.observe_at(100, start);
        tracker.observe_at(104, start);
        tracker.reset();
        assert_eq!(tracker.counters().holes_reset, 3);
        assert_eq!(tracker.missing_len(), 0);
        // After a reset the ring is re-armed around the new first sequence.
        assert!(!tracker.observe_at(7, start).duplicate);
        assert!(!tracker.observe_at(5, start).duplicate);
        tracker.observe_at(9, start);
        tracker.reconfigure(128, ms(50));
        assert_eq!(tracker.counters().holes_reset, 4);
        assert_eq!(tracker.capacity(), 128);
        assert_eq!(tracker.recovery_age(), ms(50));
        tracker.check_invariants();
    }

    /// Deterministic model check: a seeded stream with loss, bursts,
    /// reordering and duplicates, starting just below the u32 rollover, is
    /// compared with a plain set-based model of the same rules.
    #[test]
    fn tracker_matches_a_set_model_under_loss_reorder_and_duplicates() {
        use std::collections::{BTreeSet, HashSet};
        let start = Instant::now();
        let mut tracker = MissingTracker::with_limits(1 << 16, Duration::from_secs(3600));
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let base = u32::MAX - 5_000;
        let mut arrivals = Vec::new();
        let mut held = Vec::new();
        for offset in 0..20_000_u32 {
            let roll = next() % 1000;
            if roll < 30 {
                held.push(offset);
            } else if roll < 35 {
                continue;
            } else {
                arrivals.push(offset);
                if roll >= 990 {
                    arrivals.push(offset);
                }
            }
            if next() % 64 == 0 {
                arrivals.append(&mut held);
            }
        }
        arrivals.append(&mut held);

        let mut highest: Option<u32> = None;
        let mut missing = BTreeSet::new();
        let mut seen = HashSet::new();
        for (step, offset) in arrivals.into_iter().enumerate() {
            let sequence = base.wrapping_add(offset);
            let now = start + Duration::from_micros(step as u64);
            let got = tracker.observe_at(sequence, now);
            let mut newly = Vec::new();
            let (duplicate, recovered);
            if highest.map_or(true, |high| offset > high) {
                if let Some(high) = highest {
                    for gap in high + 1..offset {
                        missing.insert(gap);
                        newly.push(base.wrapping_add(gap));
                    }
                }
                highest = Some(offset);
                duplicate = false;
                recovered = false;
            } else if missing.remove(&offset) {
                duplicate = false;
                recovered = true;
            } else {
                duplicate = seen.contains(&offset);
                recovered = false;
            }
            seen.insert(offset);
            assert_eq!(got.duplicate, duplicate, "duplicate at {offset}");
            assert_eq!(got.recovered, recovered, "recovered at {offset}");
            assert_eq!(got.newly_missing, newly, "newly missing at {offset}");
            assert_eq!(tracker.missing_len(), missing.len());
            if step % 997 == 0 {
                assert_eq!(
                    tracker.missing_sequences().collect::<Vec<_>>(),
                    missing
                        .iter()
                        .map(|gap| base.wrapping_add(*gap))
                        .collect::<Vec<_>>()
                );
                tracker.check_invariants();
            }
        }
        assert_eq!(tracker.counters().late_packets, 0);
    }
}
