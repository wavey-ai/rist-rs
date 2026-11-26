use crate::auth::EapolFrame;
use crate::crypto::{PskKey, PskReceiveCounters};
use crate::endpoint::{CongestionControlMode, RecoveryConfig, RecoveryTuning};
use crate::packet::gre::{
    decode_eapol_payload, decode_encrypted_buffer_negotiation_packet,
    decode_encrypted_keepalive_packet, decode_encrypted_reduced_packet, decode_main_packet,
    encode_buffer_negotiation_payload, encode_eapol_payload,
    encode_encrypted_buffer_negotiation_payload, encode_encrypted_keepalive_payload,
    encode_encrypted_oob_payload, encode_encrypted_reduced_payload, encode_keepalive_payload,
    encode_oob_payload, encode_reduced_payload, reduced_header, BufferNegotiation,
    BufferNegotiationPacket, GreHeader, GreKeepalive, KeepalivePacket, MainPacket,
    OwnedBufferNegotiationPacket, OwnedKeepalivePacket, OwnedReducedPacket, ReducedHeader,
    ReducedPacket,
};
use crate::packet::rtcp::NackMode;
use crate::packet::rtp::RtpPacket;
use crate::simple::{
    OutboundPacket, ReceivedPayload, SimpleReceiverCore, SimpleSenderCore, SimpleSenderPeerState,
    MAX_NACK_PACKETS_PER_POLL,
};
use crate::stats::{ReceiverStats, SenderStats};
use crate::time::ntp_now;
use crate::Result;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::time::{Duration, Instant};

/// Hasher for the per-peer flow maps, keyed by flow id (the RTP SSRC with
/// the retry bit cleared). The maps hold at most `max_flows` entries, so
/// SipHash's flooding resistance buys nothing; this is one multiply.
#[derive(Debug, Clone, Copy, Default)]
struct FlowIdHasher(u64);

impl Hasher for FlowIdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_u64(self.0.rotate_left(8) ^ u64::from(byte));
        }
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        let mixed = (self.0 ^ value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = mixed ^ (mixed >> 32);
    }
}

type FlowMap<V> = HashMap<u32, V, BuildHasherDefault<FlowIdHasher>>;

pub const DEFAULT_VIRT_SRC_PORT: u16 = 1971;
pub const DEFAULT_VIRT_DST_PORT: u16 = 1968;
pub const DEFAULT_MAIN_KEEPALIVE_INTERVAL: Duration = Duration::from_millis(1000);
pub const DEFAULT_MAIN_SESSION_TIMEOUT: Duration = Duration::from_millis(2000);
pub const DEFAULT_MAIN_FLOWS_PER_PEER: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainSessionConfig {
    pub keepalive_interval: Duration,
    pub session_timeout: Duration,
}

impl Default for MainSessionConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: DEFAULT_MAIN_KEEPALIVE_INTERVAL,
            session_timeout: DEFAULT_MAIN_SESSION_TIMEOUT,
        }
    }
}

impl From<crate::endpoint::ConnectionConfig> for MainSessionConfig {
    fn from(config: crate::endpoint::ConnectionConfig) -> Self {
        Self {
            keepalive_interval: config.keepalive_interval,
            session_timeout: config.session_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainSessionPoll {
    pub keepalive_due: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone)]
pub struct MainSessionTimers {
    config: MainSessionConfig,
    next_keepalive: Option<Instant>,
    last_peer_activity: Option<Instant>,
}

impl MainSessionTimers {
    pub fn new() -> Self {
        Self::with_config(MainSessionConfig::default())
    }

    pub fn with_config(config: MainSessionConfig) -> Self {
        Self {
            config,
            next_keepalive: None,
            last_peer_activity: None,
        }
    }

    pub fn config(&self) -> MainSessionConfig {
        self.config
    }

    pub fn set_config(&mut self, config: MainSessionConfig) {
        self.config = config;
        self.next_keepalive = None;
    }

    pub fn observe_peer_activity(&mut self, now: Instant) {
        self.last_peer_activity = Some(now);
    }

    pub fn last_peer_activity(&self) -> Option<Instant> {
        self.last_peer_activity
    }

    /// When [`Self::poll`] next reports a keepalive as due (`None` before
    /// the first poll arms the timer).
    pub fn next_keepalive_at(&self) -> Option<Instant> {
        self.next_keepalive
    }

    pub fn is_timed_out(&self, now: Instant) -> bool {
        self.peer_timed_out(now)
    }

    pub fn poll(&mut self, now: Instant) -> MainSessionPoll {
        MainSessionPoll {
            keepalive_due: self.poll_keepalive(now),
            timed_out: self.peer_timed_out(now),
        }
    }

    fn poll_keepalive(&mut self, now: Instant) -> bool {
        let interval = self.config.keepalive_interval;
        let Some(due) = self.next_keepalive else {
            self.next_keepalive = Some(now + interval);
            return interval.is_zero();
        };
        if now < due {
            return false;
        }
        self.next_keepalive = Some(next_due_after(due, now, interval));
        true
    }

    fn peer_timed_out(&self, now: Instant) -> bool {
        let Some(last_activity) = self.last_peer_activity else {
            return false;
        };
        elapsed_at_least(now, last_activity, self.config.session_timeout)
    }
}

impl Default for MainSessionTimers {
    fn default() -> Self {
        Self::new()
    }
}

fn next_due_after(due: Instant, now: Instant, interval: Duration) -> Instant {
    if interval.is_zero() {
        return now;
    }
    let mut next = due + interval;
    while next <= now {
        next += interval;
    }
    next
}

fn elapsed_at_least(now: Instant, then: Instant, duration: Duration) -> bool {
    now.checked_duration_since(then)
        .map(|elapsed| elapsed >= duration)
        .unwrap_or(false)
}

/// What [`MainSenderCore::send_payload_with`] sent: the datagram's
/// sequences and length, without its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainPacketMeta {
    pub rtp_sequence: u32,
    pub gre_sequence: u32,
    pub retry: bool,
    /// The datagram's length in bytes.
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainOutboundPacket {
    pub rtp_sequence: u32,
    pub gre_sequence: u32,
    pub retry: bool,
    pub bytes: Vec<u8>,
}

/// What a Main sender owes the peer for one feedback compound: echo
/// responses (send first) and retransmissions, each wrapped in reduced GRE.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MainFeedbackOutcome {
    pub retries: Vec<MainOutboundPacket>,
    pub responses: Vec<MainControlPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainReceiverFeedback {
    pub gre_sequence: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainControlPacket {
    pub gre_sequence: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MainSenderPeerState {
    simple: SimpleSenderPeerState,
    next_gre_sequence: u32,
    tx_key: Option<PskKey>,
    rx_key: Option<PskKey>,
}

impl MainSenderPeerState {
    pub fn stats(&self) -> SenderStats {
        let mut stats = self.simple.stats();
        add_psk_counters_to_sender(&mut stats, self.rx_key.as_ref());
        stats
    }

    /// When a duplicate repair for this peer is next due.
    pub fn next_repair_at(&self) -> Option<Instant> {
        self.simple.next_repair_at()
    }

    /// Also installs a receive key for the same passphrase when there is
    /// none, so clear packets from the peer are dropped.
    pub fn set_tx_key(&mut self, key: PskKey) {
        if self.rx_key.is_none() {
            self.rx_key = rx_key_for(&key);
        }
        self.tx_key = Some(key);
    }

    /// Also installs a transmit key for the same passphrase when there is
    /// none, so the peer state never sends clear.
    pub fn set_rx_key(&mut self, key: PskKey) {
        if self.tx_key.is_none() {
            self.tx_key = tx_key_for(&key);
        }
        self.rx_key = Some(key);
    }
}

#[derive(Debug, Clone)]
pub struct MainSenderCore {
    simple: SimpleSenderCore,
    gre_version: u8,
    next_gre_sequence: u32,
    virt_src_port: u16,
    virt_dst_port: u16,
    tx_key: Option<PskKey>,
    rx_key: Option<PskKey>,
}

impl MainSenderCore {
    pub fn new(flow_id: u32, history_packets: usize) -> Self {
        Self {
            simple: SimpleSenderCore::new(flow_id, history_packets),
            gre_version: 1,
            next_gre_sequence: 0,
            virt_src_port: DEFAULT_VIRT_SRC_PORT,
            virt_dst_port: DEFAULT_VIRT_DST_PORT,
            tx_key: None,
            rx_key: None,
        }
    }

    pub fn with_ports(mut self, virt_src_port: u16, virt_dst_port: u16) -> Self {
        self.set_ports(virt_src_port, virt_dst_port);
        self
    }

    pub fn set_ports(&mut self, virt_src_port: u16, virt_dst_port: u16) {
        self.virt_src_port = virt_src_port;
        self.virt_dst_port = virt_dst_port;
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.simple
            .set_recovery_config(recovery, congestion_control);
    }

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.simple.set_recovery_tuning(tuning);
    }

    pub fn with_recovery_tuning(mut self, tuning: RecoveryTuning) -> Self {
        self.set_recovery_tuning(tuning);
        self
    }

    pub fn recovery_tuning(&self) -> RecoveryTuning {
        self.simple.recovery_tuning()
    }

    pub fn with_gre_version(mut self, gre_version: u8) -> Self {
        self.gre_version = gre_version;
        self
    }

    pub fn upgrade_gre_version(&mut self, gre_version: u8) {
        self.gre_version = self.gre_version.max(gre_version);
    }

    pub fn with_null_packet_suppression(mut self, enabled: bool) -> Self {
        self.simple = self.simple.with_null_packet_suppression(enabled);
        self
    }

    /// Also installs a receive key for the same passphrase when there is
    /// none, so clear packets from the peer are dropped.
    pub fn with_tx_key(mut self, key: PskKey) -> Self {
        self.set_tx_key(key);
        self
    }

    /// Also installs a transmit key for the same passphrase when there is
    /// none, so the endpoint never sends clear.
    pub fn with_rx_key(mut self, key: PskKey) -> Self {
        self.set_rx_key(key);
        self
    }

    pub fn with_psk(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key.clone());
        self.rx_key = Some(key);
        self
    }

    /// Also installs a receive key for the same passphrase when there is
    /// none, so clear packets from the peer are dropped.
    pub fn set_tx_key(&mut self, key: PskKey) {
        if self.rx_key.is_none() {
            self.rx_key = rx_key_for(&key);
        }
        self.tx_key = Some(key);
    }

    /// Also installs a transmit key for the same passphrase when there is
    /// none, so the endpoint never sends clear.
    pub fn set_rx_key(&mut self, key: PskKey) {
        if self.tx_key.is_none() {
            self.tx_key = tx_key_for(&key);
        }
        self.rx_key = Some(key);
    }

    pub fn enable_null_packet_suppression(&mut self) {
        self.simple.enable_null_packet_suppression();
    }

    pub fn disable_null_packet_suppression(&mut self) {
        self.simple.disable_null_packet_suppression();
    }

    pub fn null_packet_suppression_enabled(&self) -> bool {
        self.simple.null_packet_suppression_enabled()
    }

    pub fn set_next_rtp_sequence(&mut self, sequence: u32) {
        self.simple.set_next_sequence(sequence);
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> MainOutboundPacket {
        self.send_payload_with(payload, ntp_timestamp, now, |meta, head, body| {
            let mut bytes = Vec::with_capacity(meta.len);
            bytes.extend_from_slice(head);
            bytes.extend_from_slice(body);
            MainOutboundPacket {
                rtp_sequence: meta.rtp_sequence,
                gre_sequence: meta.gre_sequence,
                retry: false,
                bytes,
            }
        })
    }

    /// [`Self::send_payload`] without an owned packet: `send` gets the
    /// datagram as two parts to send back to back (`head` then `body`).
    /// Unencrypted, `head` is the GRE header on the stack and `body` the RTP
    /// packet in its send-history slot, so the payload is copied once and
    /// nothing is allocated once the history is warm. With a PSK, `head` is
    /// the whole encrypted datagram and `body` is empty.
    pub fn send_payload_with<R>(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
        send: impl FnOnce(MainPacketMeta, &[u8], &[u8]) -> R,
    ) -> R {
        let gre_sequence = self.next_gre_sequence();
        let gre_version = self.gre_version;
        let reduced = ReducedHeader {
            src_port: self.virt_src_port,
            dst_port: self.virt_dst_port,
        };
        let tx_key = &mut self.tx_key;
        self.simple
            .send_payload_with(payload, ntp_timestamp, now, |rtp_sequence, rtp| {
                if let Some(key) = tx_key {
                    let bytes = encode_encrypted_reduced_payload(
                        gre_version,
                        gre_sequence,
                        reduced,
                        rtp,
                        key,
                    );
                    let meta = MainPacketMeta {
                        rtp_sequence,
                        gre_sequence,
                        retry: false,
                        len: bytes.len(),
                    };
                    return send(meta, &bytes, &[]);
                }
                let header = reduced_header(gre_version, gre_sequence, reduced);
                let meta = MainPacketMeta {
                    rtp_sequence,
                    gre_sequence,
                    retry: false,
                    len: header.as_slice().len() + rtp.len(),
                };
                send(meta, header.as_slice(), rtp)
            })
    }

    /// [`Self::send_payload_with`] into `out`, which is cleared first: the
    /// whole datagram in a buffer the caller reuses.
    pub fn send_payload_into(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> MainPacketMeta {
        self.send_payload_with(payload, ntp_timestamp, now, |meta, head, body| {
            out.clear();
            out.extend_from_slice(head);
            out.extend_from_slice(body);
            meta
        })
    }

    pub fn prepare_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> OutboundPacket {
        self.simple.send_payload(payload, ntp_timestamp, now)
    }

    pub fn new_peer_state(&self) -> MainSenderPeerState {
        MainSenderPeerState {
            simple: self.simple.new_peer_state(),
            next_gre_sequence: 0,
            // Its own nonce: this peer's GRE sequence also starts at 0.
            tx_key: self.tx_key.as_ref().map(PskKey::fresh_sender_copy),
            rx_key: self.rx_key.as_ref().map(PskKey::fresh_copy),
        }
    }

    pub fn wrap_payload_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        packet: &OutboundPacket,
    ) -> MainOutboundPacket {
        state.simple.record_send(packet.bytes.len());
        self.wrap_rtp_for_peer(state, packet.sequence, packet.retry, &packet.bytes)
    }

    pub fn handle_feedback(&mut self, packet: &[u8]) -> Result<Vec<MainOutboundPacket>> {
        let packet = self.decode_reduced(packet)?;
        self.handle_reduced_feedback(packet.reduced(), packet.payload())
    }

    /// Retransmissions for one feedback compound. Echo requests in it are
    /// not answered; use [`Self::handle_reduced_feedback_outcome`].
    pub fn handle_reduced_feedback(
        &mut self,
        reduced: ReducedHeader,
        payload: &[u8],
    ) -> Result<Vec<MainOutboundPacket>> {
        Ok(self
            .handle_reduced_feedback_outcome(reduced, payload, ntp_now(), Instant::now())?
            .retries)
    }

    /// Handles one feedback compound: RTT samples from echo responses,
    /// answers to echo requests and retransmissions, all wrapped.
    pub fn handle_reduced_feedback_outcome(
        &mut self,
        _reduced: ReducedHeader,
        payload: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<MainFeedbackOutcome> {
        let outcome = self
            .simple
            .handle_feedback_outcome_at(payload, now_ntp, now)?;
        let responses = outcome
            .responses
            .iter()
            .map(|response| self.wrap_control_payload(response))
            .collect();
        let retries = outcome
            .retries
            .into_iter()
            .map(|retry| self.wrap_rtp(retry.sequence, true, &retry.bytes))
            .collect();
        Ok(MainFeedbackOutcome { retries, responses })
    }

    pub fn handle_feedback_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        packet: &[u8],
    ) -> Result<Vec<MainOutboundPacket>> {
        let packet = decode_reduced_for_peer(state, packet)?;
        self.handle_reduced_feedback_for_peer(state, packet.payload())
    }

    pub fn handle_reduced_feedback_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        payload: &[u8],
    ) -> Result<Vec<MainOutboundPacket>> {
        Ok(self
            .handle_reduced_feedback_outcome_for_peer(state, payload, ntp_now(), Instant::now())?
            .retries)
    }

    /// [`Self::handle_reduced_feedback_outcome`] for one peer of a
    /// multi-peer sender.
    pub fn handle_reduced_feedback_outcome_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        payload: &[u8],
        now_ntp: u64,
        now: Instant,
    ) -> Result<MainFeedbackOutcome> {
        let outcome = self.simple.handle_feedback_outcome_for_peer_at(
            &mut state.simple,
            payload,
            now_ntp,
            now,
        )?;
        let responses = outcome
            .responses
            .iter()
            .map(|response| self.wrap_control_for_peer(state, response))
            .collect();
        let retries = outcome
            .retries
            .into_iter()
            .map(|retry| self.wrap_rtp_for_peer(state, retry.sequence, true, &retry.bytes))
            .collect();
        Ok(MainFeedbackOutcome { retries, responses })
    }

    /// Repairs the sender sends on its own, due at `now` (see
    /// [`SimpleSenderCore::poll_repairs_at`]), wrapped.
    pub fn poll_repairs(&mut self, now: Instant) -> Vec<MainOutboundPacket> {
        self.simple
            .poll_repairs_at(now)
            .into_iter()
            .map(|repair| self.wrap_rtp(repair.sequence, true, &repair.bytes))
            .collect()
    }

    /// [`Self::poll_repairs`], at most `limit` of them (see
    /// [`SimpleSenderCore::poll_repairs_limited_at`]).
    pub fn poll_repairs_limited(&mut self, now: Instant, limit: usize) -> Vec<MainOutboundPacket> {
        self.simple
            .poll_repairs_limited_at(now, limit)
            .into_iter()
            .map(|repair| self.wrap_rtp(repair.sequence, true, &repair.bytes))
            .collect()
    }

    /// Drops the repairs due at `now` unsent (see
    /// [`SimpleSenderCore::discard_due_repairs_at`]).
    pub fn discard_due_repairs(&mut self, now: Instant) -> usize {
        self.simple.discard_due_repairs_at(now)
    }

    /// Takes back a retransmission of RTP sequence `rtp_sequence` that
    /// could not be sent (see [`SimpleSenderCore::retransmit_not_sent`]).
    pub fn retransmit_not_sent(&mut self, rtp_sequence: u32) {
        self.simple.retransmit_not_sent(rtp_sequence);
    }

    /// [`Self::retransmit_not_sent`] for one peer of a multi-peer sender.
    pub fn retransmit_not_sent_for_peer(&self, state: &mut MainSenderPeerState, rtp_sequence: u32) {
        self.simple
            .retransmit_not_sent_for_peer(&mut state.simple, rtp_sequence);
    }

    /// [`Self::poll_repairs`] for one peer of a multi-peer sender.
    pub fn poll_repairs_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        now: Instant,
    ) -> Vec<MainOutboundPacket> {
        self.poll_repairs_for_peer_limited(state, now, usize::MAX)
    }

    /// [`Self::poll_repairs_limited`] for one peer of a multi-peer sender.
    pub fn poll_repairs_for_peer_limited(
        &self,
        state: &mut MainSenderPeerState,
        now: Instant,
        limit: usize,
    ) -> Vec<MainOutboundPacket> {
        self.simple
            .poll_repairs_for_peer_limited_at(&mut state.simple, now, limit)
            .into_iter()
            .map(|repair| self.wrap_rtp_for_peer(state, repair.sequence, true, &repair.bytes))
            .collect()
    }

    /// [`Self::discard_due_repairs`] for one peer of a multi-peer sender.
    pub fn discard_due_repairs_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        now: Instant,
    ) -> usize {
        self.simple
            .discard_due_repairs_for_peer_at(&mut state.simple, now)
    }

    pub fn next_repair_at(&self) -> Option<Instant> {
        self.simple.next_repair_at()
    }

    pub fn next_rtcp_at(&self) -> Option<Instant> {
        self.simple.next_rtcp_at()
    }

    pub fn poll_rtcp(&mut self, now: Instant, ntp_timestamp: u64) -> Option<MainControlPacket> {
        let packet = self.poll_rtcp_payload(now, ntp_timestamp)?;
        Some(self.wrap_control_payload(&packet))
    }

    pub fn poll_rtcp_payload(&mut self, now: Instant, ntp_timestamp: u64) -> Option<Vec<u8>> {
        self.simple.poll_rtcp(now, ntp_timestamp)
    }

    pub fn wrap_control_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        payload: &[u8],
    ) -> MainControlPacket {
        let gre_sequence = next_peer_gre_sequence(state);
        let reduced = ReducedHeader {
            src_port: self.virt_src_port,
            dst_port: self.virt_dst_port,
        };
        let bytes = if let Some(key) = &mut state.tx_key {
            encode_encrypted_reduced_payload(self.gre_version, gre_sequence, reduced, payload, key)
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, payload)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_keepalive_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        keepalive: GreKeepalive<'_>,
    ) -> MainControlPacket {
        let gre_sequence = next_peer_gre_sequence(state);
        let bytes = if let Some(key) = &mut state.tx_key {
            encode_encrypted_keepalive_payload(self.gre_version, gre_sequence, keepalive, key)
        } else {
            encode_keepalive_payload(self.gre_version, gre_sequence, keepalive)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_eapol_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        frame: &EapolFrame,
    ) -> Result<MainControlPacket> {
        let gre_sequence = next_peer_gre_sequence(state);
        Ok(MainControlPacket {
            gre_sequence,
            bytes: encode_eapol_payload(self.gre_version, gre_sequence, frame)?,
        })
    }

    pub fn decode_datagram_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        packet: &[u8],
    ) -> Result<MainPacket> {
        decode_main_packet(packet, state.rx_key.as_mut())
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_keepalive_payload(self.gre_version, gre_sequence, keepalive, key)
        } else {
            encode_keepalive_payload(self.gre_version, gre_sequence, keepalive)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_buffer_negotiation_payload(gre_sequence, negotiation, key)
        } else {
            encode_buffer_negotiation_payload(gre_sequence, negotiation)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_eapol(&mut self, frame: &EapolFrame) -> Result<MainControlPacket> {
        let gre_sequence = self.next_gre_sequence();
        Ok(MainControlPacket {
            gre_sequence,
            bytes: encode_eapol_payload(self.gre_version, gre_sequence, frame)?,
        })
    }

    pub fn build_oob(&mut self, payload: &[u8]) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_oob_payload(self.gre_version, gre_sequence, payload, key)
        } else {
            encode_oob_payload(self.gre_version, gre_sequence, payload)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn accept_keepalive(&mut self, packet: &[u8]) -> Result<OwnedKeepalivePacket> {
        accept_keepalive_with(self.rx_key.as_mut(), packet)
    }

    pub fn accept_buffer_negotiation(
        &mut self,
        packet: &[u8],
    ) -> Result<OwnedBufferNegotiationPacket> {
        accept_buffer_negotiation_with(self.rx_key.as_mut(), packet)
    }

    pub fn accept_eapol(&mut self, packet: &[u8]) -> Result<EapolFrame> {
        Ok(decode_eapol_payload(packet)?.frame)
    }

    pub fn decode_datagram(&mut self, packet: &[u8]) -> Result<MainPacket> {
        decode_main_packet(packet, self.rx_key.as_mut())
    }

    /// Whether a receive key is configured (then every packet but EAPOL
    /// must arrive encrypted).
    pub fn has_rx_key(&self) -> bool {
        self.rx_key.is_some()
    }

    /// A copy of the receive key with no history, for one candidate
    /// source: a listening sender decrypts each source's packets with its
    /// own copy until it has chosen its peer, so packets from one source
    /// can never shut out another's nonce. Copies share one budget of
    /// nonce changes ([`crate::crypto::MAX_SHARED_RECEIVE_REKEYS_PER_SECOND`]).
    pub fn fresh_rx_key(&self) -> Option<PskKey> {
        self.rx_key.as_ref().map(PskKey::fresh_copy)
    }

    /// [`Self::decode_datagram`] with a receive key of the caller's (one
    /// from [`Self::fresh_rx_key`]).
    pub fn decode_datagram_with_rx_key(
        &self,
        key: &mut PskKey,
        packet: &[u8],
    ) -> Result<MainPacket> {
        decode_main_packet(packet, Some(key))
    }

    /// Makes `key` (a candidate's copy from [`Self::fresh_rx_key`]) the
    /// receive key, keeping the counters of the one it replaces. Does
    /// nothing without a receive key.
    pub fn adopt_rx_key(&mut self, mut key: PskKey) {
        if let Some(current) = &self.rx_key {
            key.absorb_counters(current.receive_counters());
            self.rx_key = Some(key);
        }
    }

    /// Adds the counters of a receive-key copy that is being dropped to
    /// the receive key's, so stats keep them.
    pub fn absorb_psk_counters(&mut self, counters: PskReceiveCounters) {
        if let Some(key) = &mut self.rx_key {
            key.absorb_counters(counters);
        }
    }

    pub fn stats(&self) -> SenderStats {
        let mut stats = self.simple.stats();
        add_psk_counters_to_sender(&mut stats, self.rx_key.as_ref());
        stats
    }

    fn wrap_rtp_for_peer(
        &self,
        state: &mut MainSenderPeerState,
        rtp_sequence: u32,
        retry: bool,
        rtp_packet: &[u8],
    ) -> MainOutboundPacket {
        let gre_sequence = next_peer_gre_sequence(state);
        let reduced = ReducedHeader {
            src_port: self.virt_src_port,
            dst_port: self.virt_dst_port,
        };
        let bytes = if let Some(key) = &mut state.tx_key {
            encode_encrypted_reduced_payload(
                self.gre_version,
                gre_sequence,
                reduced,
                rtp_packet,
                key,
            )
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, rtp_packet)
        };
        MainOutboundPacket {
            rtp_sequence,
            gre_sequence,
            retry,
            bytes,
        }
    }

    fn wrap_rtp(
        &mut self,
        rtp_sequence: u32,
        retry: bool,
        rtp_packet: &[u8],
    ) -> MainOutboundPacket {
        let gre_sequence = self.next_gre_sequence();
        let reduced = ReducedHeader {
            src_port: self.virt_src_port,
            dst_port: self.virt_dst_port,
        };
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_reduced_payload(
                self.gre_version,
                gre_sequence,
                reduced,
                rtp_packet,
                key,
            )
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, rtp_packet)
        };
        MainOutboundPacket {
            rtp_sequence,
            gre_sequence,
            retry,
            bytes,
        }
    }

    fn wrap_control_payload(&mut self, payload: &[u8]) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let reduced = ReducedHeader {
            src_port: self.virt_src_port,
            dst_port: self.virt_dst_port,
        };
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_reduced_payload(self.gre_version, gre_sequence, reduced, payload, key)
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, payload)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    fn next_gre_sequence(&mut self) -> u32 {
        let sequence = self.next_gre_sequence;
        self.next_gre_sequence = self.next_gre_sequence.wrapping_add(1);
        sequence
    }

    fn decode_reduced<'a>(&mut self, packet: &'a [u8]) -> Result<DecodedReduced<'a>> {
        decode_reduced_with(self.rx_key.as_mut(), packet)
    }
}

fn next_peer_gre_sequence(state: &mut MainSenderPeerState) -> u32 {
    let sequence = state.next_gre_sequence;
    state.next_gre_sequence = state.next_gre_sequence.wrapping_add(1);
    sequence
}

fn decode_reduced_for_peer<'a>(
    state: &mut MainSenderPeerState,
    packet: &'a [u8],
) -> Result<DecodedReduced<'a>> {
    decode_reduced_with(state.rx_key.as_mut(), packet)
}

/// Decodes a reduced packet. With a receive key it must be encrypted and
/// pass the PSK checks (a clear one is dropped and counted); without one
/// an encrypted packet cannot be read.
fn decode_reduced_with<'a>(
    rx_key: Option<&mut PskKey>,
    packet: &'a [u8],
) -> Result<DecodedReduced<'a>> {
    if let Some(key) = rx_key {
        return Ok(DecodedReduced::Owned(decode_encrypted_reduced_packet(
            packet, key,
        )?));
    }
    let (gre, _) = GreHeader::decode(packet)?;
    if gre.key.is_some() {
        return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
    }
    Ok(DecodedReduced::Borrowed(ReducedPacket::decode(packet)?))
}

/// [`decode_reduced_with`] for keepalives.
fn accept_keepalive_with(
    rx_key: Option<&mut PskKey>,
    packet: &[u8],
) -> Result<OwnedKeepalivePacket> {
    if let Some(key) = rx_key {
        return decode_encrypted_keepalive_packet(packet, key);
    }
    let (gre, _) = GreHeader::decode(packet)?;
    if gre.key.is_some() {
        return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
    }
    Ok(KeepalivePacket::decode(packet)?.into_owned())
}

/// [`decode_reduced_with`] for buffer negotiation.
fn accept_buffer_negotiation_with(
    rx_key: Option<&mut PskKey>,
    packet: &[u8],
) -> Result<OwnedBufferNegotiationPacket> {
    if let Some(key) = rx_key {
        return decode_encrypted_buffer_negotiation_packet(packet, key);
    }
    let (gre, _) = GreHeader::decode(packet)?;
    if gre.key.is_some() {
        return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
    }
    Ok(BufferNegotiationPacket::decode(packet)?.into_owned())
}

/// The transmit key an endpoint uses when it was given only a receive key:
/// one for the same passphrase, so nothing but EAPOL goes out clear.
fn tx_key_for(rx_key: &PskKey) -> Option<PskKey> {
    Some(rx_key.sender_for())
}

/// The receive key an endpoint uses when it was given only a transmit key:
/// one for the same passphrase, so it drops clear packets from its peer.
fn rx_key_for(tx_key: &PskKey) -> Option<PskKey> {
    Some(tx_key.receiver_for())
}

fn add_psk_counters_to_receiver(stats: &mut ReceiverStats, key: Option<&PskKey>) {
    if let Some(key) = key {
        let counters = key.receive_counters();
        stats.clear_packets_dropped += counters.clear_packets_dropped;
        stats.decrypt_rejected += counters.decrypt_rejected;
        stats.decrypt_latched += counters.decrypt_latched;
        stats.nonce_latches += counters.nonce_latches;
    }
}

fn add_psk_counters_to_sender(stats: &mut SenderStats, key: Option<&PskKey>) {
    if let Some(key) = key {
        let counters = key.receive_counters();
        stats.clear_packets_dropped += counters.clear_packets_dropped;
        stats.decrypt_rejected += counters.decrypt_rejected;
        stats.decrypt_latched += counters.decrypt_latched;
        stats.nonce_latches += counters.nonce_latches;
    }
}

#[derive(Debug, Clone)]
pub struct MainReceiverCore {
    primary_flow_id: u32,
    cname: String,
    nack_mode: NackMode,
    flows: FlowMap<SimpleReceiverCore>,
    /// Flow ids in ascending order (flows are never removed).
    flow_order: Vec<u32>,
    max_flows: usize,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
    tuning: RecoveryTuning,
    gre_version: u8,
    next_gre_sequence: u32,
    last_reduced: Option<ReducedHeader>,
    flow_reduced: FlowMap<ReducedHeader>,
    tx_key: Option<PskKey>,
    rx_key: Option<PskKey>,
}

impl MainReceiverCore {
    pub fn new(flow_id: u32, cname: impl Into<String>, nack_mode: NackMode) -> Self {
        let cname = cname.into();
        let mut flows = FlowMap::default();
        flows.insert(
            flow_id,
            SimpleReceiverCore::new(flow_id, cname.clone(), nack_mode),
        );
        Self {
            primary_flow_id: flow_id,
            cname,
            nack_mode,
            flows,
            flow_order: vec![flow_id],
            max_flows: DEFAULT_MAIN_FLOWS_PER_PEER,
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
            tuning: RecoveryTuning::default(),
            gre_version: 1,
            next_gre_sequence: 0,
            last_reduced: None,
            flow_reduced: FlowMap::default(),
            tx_key: None,
            rx_key: None,
        }
    }

    pub fn with_gre_version(mut self, gre_version: u8) -> Self {
        self.gre_version = gre_version;
        self
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        for flow in self.flows.values_mut() {
            flow.set_recovery_config(recovery.clone(), congestion_control);
        }
        self.recovery = recovery;
        self.congestion_control = congestion_control;
    }

    pub fn with_recovery_tuning(mut self, tuning: RecoveryTuning) -> Self {
        self.set_recovery_tuning(tuning);
        self
    }

    /// Applies `tuning` to every flow, present and future.
    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        for flow in self.flows.values_mut() {
            flow.set_recovery_tuning(tuning);
        }
        self.tuning = tuning;
    }

    pub fn recovery_tuning(&self) -> RecoveryTuning {
        self.tuning
    }

    /// The earliest [`SimpleReceiverCore::next_poll_at`] of all flows.
    pub fn next_poll_at(&self) -> Option<Instant> {
        self.flows
            .values()
            .filter_map(SimpleReceiverCore::next_poll_at)
            .min()
    }

    /// Also installs a receive key for the same passphrase when there is
    /// none, so clear packets from the peer are dropped.
    pub fn with_tx_key(mut self, key: PskKey) -> Self {
        self.set_tx_key(key);
        self
    }

    /// Also installs a transmit key for the same passphrase when there is
    /// none, so the endpoint never sends clear.
    pub fn with_rx_key(mut self, key: PskKey) -> Self {
        self.set_rx_key(key);
        self
    }

    pub fn with_psk(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key.clone());
        self.rx_key = Some(key);
        self
    }

    /// Also installs a receive key for the same passphrase when there is
    /// none, so clear packets from the peer are dropped.
    pub fn set_tx_key(&mut self, key: PskKey) {
        if self.rx_key.is_none() {
            self.rx_key = rx_key_for(&key);
        }
        self.tx_key = Some(key);
    }

    /// Also installs a transmit key for the same passphrase when there is
    /// none, so the endpoint never sends clear.
    pub fn set_rx_key(&mut self, key: PskKey) {
        if self.tx_key.is_none() {
            self.tx_key = tx_key_for(&key);
        }
        self.rx_key = Some(key);
    }

    pub fn decode_datagram(&mut self, packet: &[u8]) -> Result<MainPacket> {
        decode_main_packet(packet, self.rx_key.as_mut())
    }

    pub fn fresh_session(&self) -> Self {
        let mut session = Self::new(self.primary_flow_id, self.cname.clone(), self.nack_mode)
            .with_gre_version(self.gre_version);
        session.set_recovery_config(self.recovery.clone(), self.congestion_control);
        session.set_recovery_tuning(self.tuning);
        session.max_flows = self.max_flows;
        if let Some(key) = &self.tx_key {
            // Its own nonce: the session's GRE sequence also starts at 0.
            session.set_tx_key(key.fresh_sender_copy());
        }
        if let Some(key) = &self.rx_key {
            session.set_rx_key(key.fresh_copy());
        }
        session
    }

    /// Whether a receive key is configured (then every packet but EAPOL
    /// must arrive encrypted).
    pub fn has_rx_key(&self) -> bool {
        self.rx_key.is_some()
    }

    /// With a receive key, drops (and counts) a datagram that arrived
    /// clear, other than EAPOL, before any session state is made for it.
    pub fn screen_clear_datagram(&mut self, packet: &[u8]) -> Result<()> {
        match &mut self.rx_key {
            Some(key) => crate::packet::gre::screen_clear_datagram(packet, key),
            None => Ok(()),
        }
    }

    /// Whether this session's source has shown it holds the passphrase:
    /// always true without a receive key; with one, true once a packet
    /// passed the checks with a strong verdict (RTP data or RTCP) under a
    /// nonce that is still tracked and not shut out
    /// ([`PskKey::receive_proven`]). Keepalives, buffer negotiation and
    /// out-of-band packets pass with a weak verdict that a host with no key
    /// gets every time, so a session that has sent only those is not
    /// proven: an endpoint should not take it as its peer (send it
    /// feedback or keepalives) or count its packets as peer activity.
    pub fn rx_peer_proven(&self) -> bool {
        self.rx_key.as_ref().map_or(true, PskKey::receive_proven)
    }

    /// What the receive key turned away (zero without a key).
    pub fn psk_receive_counters(&self) -> PskReceiveCounters {
        self.rx_key
            .as_ref()
            .map(PskKey::receive_counters)
            .unwrap_or_default()
    }

    pub fn accept_packet(&mut self, packet: &[u8]) -> Result<ReceivedPayload> {
        let packet = self.decode_reduced(packet)?;
        self.accept_reduced(packet.reduced(), packet.payload())
    }

    pub fn accept_reduced(
        &mut self,
        reduced: ReducedHeader,
        payload: &[u8],
    ) -> Result<ReceivedPayload> {
        self.accept_reduced_at(reduced, payload, Instant::now())
    }

    /// [`Self::accept_reduced`] with the caller's clock reading.
    pub fn accept_reduced_at(
        &mut self,
        reduced: ReducedHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<ReceivedPayload> {
        self.last_reduced = Some(reduced);
        let mut packet = RtpPacket::decode(payload)?;
        let retry = packet.header.ssrc & 1 == 1;
        let flow_id = packet.header.ssrc & !1;
        packet.header.ssrc = flow_id;
        self.flow_reduced.insert(flow_id, reduced);
        self.flow_mut(flow_id)?
            .accept_rtp_packet_with_retry_at(packet, retry, now)
    }

    pub fn build_feedback(&mut self) -> MainReceiverFeedback {
        let feedback = self
            .flows
            .get_mut(&self.primary_flow_id)
            .expect("primary Main receiver flow must exist")
            .build_feedback_and_record();
        self.wrap_feedback_payload(&feedback)
    }

    pub fn poll_rtcp(&mut self, now: Instant, now_ntp: u64) -> Option<MainReceiverFeedback> {
        let packet = self
            .flows
            .get_mut(&self.primary_flow_id)
            .expect("primary Main receiver flow must exist")
            .poll_rtcp(now, now_ntp)?;
        Some(self.wrap_feedback_payload(&packet))
    }

    pub fn poll_rtcp_all(
        &mut self,
        now: Instant,
        now_ntp: u64,
    ) -> Vec<(u32, MainReceiverFeedback)> {
        let mut due = Vec::new();
        self.poll_rtcp_all_with(now, now_ntp, |flow_id, feedback| {
            due.push((flow_id, feedback));
            true
        });
        due
    }

    /// [`Self::poll_rtcp_all`] for a transport that sends each packet as it
    /// is built: `send` puts one wrapped packet of a flow on the wire and
    /// returns whether it went out. Flows are polled in ascending flow-id
    /// order, each for up to [`MAX_NACK_PACKETS_PER_POLL`] packets. Holes
    /// count as requested only once `send` accepted their packet (see
    /// [`SimpleReceiverCore::poll_rtcp_with`]). After the first refusal no
    /// further packet is built: the refused packet's holes and every later
    /// due hole stay due for the next poll. Returns the number of packets
    /// `send` accepted.
    pub fn poll_rtcp_all_with<F>(&mut self, now: Instant, now_ntp: u64, mut send: F) -> usize
    where
        F: FnMut(u32, MainReceiverFeedback) -> bool,
    {
        let Self {
            flows,
            flow_order,
            flow_reduced,
            gre_version,
            next_gre_sequence,
            tx_key,
            ..
        } = self;
        let mut accepted = 0;
        let mut refused = false;
        for &flow_id in flow_order.iter() {
            if refused {
                break;
            }
            let reduced = reply_reduced(flow_reduced.get(&flow_id).copied());
            accepted += flows
                .get_mut(&flow_id)
                .expect("listed Main receiver flow must exist")
                .poll_rtcp_with(now, now_ntp, MAX_NACK_PACKETS_PER_POLL, |packet| {
                    let feedback = wrap_receiver_feedback(
                        *gre_version,
                        next_gre_sequence,
                        tx_key,
                        reduced,
                        packet,
                    );
                    refused = !send(flow_id, feedback);
                    !refused
                });
        }
        accepted
    }

    pub fn handle_rtcp(
        &mut self,
        packet: &[u8],
        now_ntp: u64,
    ) -> Result<Vec<MainReceiverFeedback>> {
        let packet = self.decode_reduced(packet)?;
        self.handle_reduced_rtcp(packet.reduced(), packet.payload(), now_ntp)
    }

    pub fn handle_reduced_rtcp(
        &mut self,
        reduced: ReducedHeader,
        payload: &[u8],
        now_ntp: u64,
    ) -> Result<Vec<MainReceiverFeedback>> {
        self.last_reduced = Some(reduced);
        let flow_id = rtcp_flow_id(payload).unwrap_or(self.primary_flow_id);
        self.flow_reduced.insert(flow_id, reduced);
        let responses = self.flow_mut(flow_id)?.handle_rtcp_at(payload, now_ntp)?;
        Ok(responses
            .into_iter()
            .map(|response| self.wrap_feedback_payload_for_flow(flow_id, &response))
            .collect())
    }

    fn wrap_feedback_payload(&mut self, feedback: &[u8]) -> MainReceiverFeedback {
        let reduced = reply_reduced(self.last_reduced);
        self.wrap_feedback_with_reduced(reduced, feedback)
    }

    fn wrap_feedback_payload_for_flow(
        &mut self,
        flow_id: u32,
        feedback: &[u8],
    ) -> MainReceiverFeedback {
        let reduced = reply_reduced(self.flow_reduced.get(&flow_id).copied());
        self.wrap_feedback_with_reduced(reduced, feedback)
    }

    fn wrap_feedback_with_reduced(
        &mut self,
        reduced: ReducedHeader,
        feedback: &[u8],
    ) -> MainReceiverFeedback {
        wrap_receiver_feedback(
            self.gre_version,
            &mut self.next_gre_sequence,
            &mut self.tx_key,
            reduced,
            feedback,
        )
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_keepalive_payload(self.gre_version, gre_sequence, keepalive, key)
        } else {
            encode_keepalive_payload(self.gre_version, gre_sequence, keepalive)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_buffer_negotiation_payload(gre_sequence, negotiation, key)
        } else {
            encode_buffer_negotiation_payload(gre_sequence, negotiation)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_eapol(&mut self, frame: &EapolFrame) -> Result<MainControlPacket> {
        let gre_sequence = self.next_gre_sequence();
        Ok(MainControlPacket {
            gre_sequence,
            bytes: encode_eapol_payload(self.gre_version, gre_sequence, frame)?,
        })
    }

    pub fn build_oob(&mut self, payload: &[u8]) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_oob_payload(self.gre_version, gre_sequence, payload, key)
        } else {
            encode_oob_payload(self.gre_version, gre_sequence, payload)
        };
        MainControlPacket {
            gre_sequence,
            bytes,
        }
    }

    pub fn accept_keepalive(&mut self, packet: &[u8]) -> Result<OwnedKeepalivePacket> {
        accept_keepalive_with(self.rx_key.as_mut(), packet)
    }

    pub fn accept_buffer_negotiation(
        &mut self,
        packet: &[u8],
    ) -> Result<OwnedBufferNegotiationPacket> {
        accept_buffer_negotiation_with(self.rx_key.as_mut(), packet)
    }

    pub fn accept_eapol(&mut self, packet: &[u8]) -> Result<EapolFrame> {
        Ok(decode_eapol_payload(packet)?.frame)
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.flows
            .get(&self.primary_flow_id)
            .expect("primary Main receiver flow must exist")
            .missing_sequences()
    }

    /// The primary flow's statistics, with the session's PSK counters.
    pub fn stats(&self) -> ReceiverStats {
        let mut stats = self
            .flows
            .get(&self.primary_flow_id)
            .expect("primary Main receiver flow must exist")
            .stats();
        add_psk_counters_to_receiver(&mut stats, self.rx_key.as_ref());
        stats
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn max_flows(&self) -> usize {
        self.max_flows
    }

    pub fn set_max_flows(&mut self, max_flows: usize) -> Result<()> {
        if max_flows == 0 || self.flows.len() > max_flows {
            return Err(crate::Error::MainFlowCapacityExceeded { maximum: max_flows });
        }
        self.max_flows = max_flows;
        Ok(())
    }

    pub fn flow_ids(&self) -> Vec<u32> {
        self.flow_order.clone()
    }

    pub fn stats_for_flow(&self, flow_id: u32) -> Option<ReceiverStats> {
        self.flows.get(&flow_id).map(SimpleReceiverCore::stats)
    }

    pub fn missing_sequences_for_flow(&self, flow_id: u32) -> Option<Vec<u32>> {
        self.flows
            .get(&flow_id)
            .map(SimpleReceiverCore::missing_sequences)
    }

    fn next_gre_sequence(&mut self) -> u32 {
        let sequence = self.next_gre_sequence;
        self.next_gre_sequence = self.next_gre_sequence.wrapping_add(1);
        sequence
    }

    fn flow_mut(&mut self, flow_id: u32) -> Result<&mut SimpleReceiverCore> {
        let flows = self.flows.len();
        match self.flows.entry(flow_id) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                if flows >= self.max_flows {
                    return Err(crate::Error::MainFlowCapacityExceeded {
                        maximum: self.max_flows,
                    });
                }
                let position = self.flow_order.partition_point(|id| *id < flow_id);
                self.flow_order.insert(position, flow_id);
                Ok(entry.insert(
                    SimpleReceiverCore::new(flow_id, self.cname.clone(), self.nack_mode)
                        .with_recovery_config(self.recovery.clone(), self.congestion_control)
                        .with_recovery_tuning(self.tuning),
                ))
            }
        }
    }

    fn decode_reduced<'a>(&mut self, packet: &'a [u8]) -> Result<DecodedReduced<'a>> {
        decode_reduced_with(self.rx_key.as_mut(), packet)
    }
}

fn rtcp_flow_id(payload: &[u8]) -> Option<u32> {
    (payload.len() >= 8).then(|| u32::from_be_bytes(payload[4..8].try_into().unwrap()) & !1)
}

enum DecodedReduced<'a> {
    Borrowed(ReducedPacket<'a>),
    Owned(OwnedReducedPacket),
}

impl DecodedReduced<'_> {
    fn reduced(&self) -> ReducedHeader {
        match self {
            Self::Borrowed(packet) => packet.reduced,
            Self::Owned(packet) => packet.reduced,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Borrowed(packet) => packet.payload,
            Self::Owned(packet) => &packet.payload,
        }
    }
}

/// Wraps one receiver RTCP compound in a reduced-overhead GRE packet (and
/// encrypts it with `tx_key`), consuming one GRE sequence.
fn wrap_receiver_feedback(
    gre_version: u8,
    next_gre_sequence: &mut u32,
    tx_key: &mut Option<PskKey>,
    reduced: ReducedHeader,
    feedback: &[u8],
) -> MainReceiverFeedback {
    let gre_sequence = *next_gre_sequence;
    *next_gre_sequence = gre_sequence.wrapping_add(1);
    let bytes = if let Some(key) = tx_key {
        encode_encrypted_reduced_payload(gre_version, gre_sequence, reduced, feedback, key)
    } else {
        encode_reduced_payload(gre_version, gre_sequence, reduced, feedback)
    };
    MainReceiverFeedback {
        gre_sequence,
        bytes,
    }
}

fn reply_reduced(flow_reduced: Option<ReducedHeader>) -> ReducedHeader {
    flow_reduced
        .map(|reduced| ReducedHeader {
            src_port: reduced.dst_port,
            dst_port: reduced.src_port,
        })
        .unwrap_or(ReducedHeader {
            src_port: DEFAULT_VIRT_DST_PORT,
            dst_port: DEFAULT_VIRT_SRC_PORT,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{EapPacket, EAPOL_VERSION_3};
    use crate::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use crate::packet::gre::{
        BufferNegotiationPacket, KeepalivePacket, GRE_PROTOCOL_TYPE_KEEPALIVE,
        GRE_PROTOCOL_TYPE_REDUCED, KEEPALIVE_CAP1_NULL_PACKET_DELETION,
        KEEPALIVE_CAP2_REDUCED_OVERHEAD,
    };
    use crate::packet::rtcp::{decode_compound, Echo, EchoKind, RtcpPacket, SenderReport};
    use crate::packet::rtp::RtpPacket;
    use crate::time::{mpegts_rtp_timestamp, ntp_from_unix_duration};
    use std::time::Duration;

    #[test]
    fn send_payload_with_sends_the_same_datagram_from_the_history_slot() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut owned = MainSenderCore::new(0x1122_3344, 64).with_gre_version(2);
        let mut borrowed = MainSenderCore::new(0x1122_3344, 64).with_gre_version(2);
        let mut out = Vec::new();
        for n in 0..100u32 {
            let payload = vec![n as u8; 1_316];
            let expected = owned.send_payload(&payload, ntp, now);
            let meta = if n % 2 == 0 {
                borrowed.send_payload_with(&payload, ntp, now, |meta, head, body| {
                    out.clear();
                    out.extend_from_slice(head);
                    out.extend_from_slice(body);
                    // GRE (8), VSF (4), ports (4); the RTP packet apart.
                    assert_eq!(head.len(), 16);
                    assert_eq!(body.len(), 12 + 1_316);
                    meta
                })
            } else {
                borrowed.send_payload_into(&payload, ntp, now, &mut out)
            };
            assert_eq!(out, expected.bytes, "packet {n}");
            assert_eq!(meta.rtp_sequence, expected.rtp_sequence);
            assert_eq!(meta.gre_sequence, expected.gre_sequence);
            assert_eq!(meta.len, expected.bytes.len());
            assert!(!meta.retry);
        }
        assert_eq!(borrowed.stats().sent_packets, 100);
        assert_eq!(borrowed.stats().sent_bytes, owned.stats().sent_bytes);
    }

    #[test]
    fn send_payload_with_encrypts_into_one_part() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender =
            MainSenderCore::new(0x1122_3344, 64).with_tx_key(PskKey::new(256, b"secret").unwrap());
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(256, b"secret").unwrap());
        for n in 0..3u8 {
            let datagram = sender.send_payload_with(&[n; 188], ntp, now, |meta, head, body| {
                assert!(body.is_empty());
                assert_eq!(meta.len, head.len());
                head.to_vec()
            });
            assert!(GreHeader::decode(&datagram).unwrap().0.key.is_some());
            let received = receiver.accept_packet(&datagram).unwrap();
            assert_eq!(received.sequence, u32::from(n));
            assert_eq!(received.payload, vec![n; 188]);
        }
    }

    #[test]
    fn main_profile_wraps_rtp_in_reduced_gre() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let packet = sender.send_payload(b"payload", ntp, now);
        let decoded = ReducedPacket::decode(&packet.bytes).unwrap();
        assert_eq!(decoded.gre.version, 1);
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_REDUCED);
        assert_eq!(decoded.gre.sequence, Some(0));
        assert_eq!(decoded.reduced.src_port, DEFAULT_VIRT_SRC_PORT);
        assert_eq!(decoded.reduced.dst_port, DEFAULT_VIRT_DST_PORT);
        assert_eq!(decoded.payload[0], 0x80);
        assert_eq!(decoded.payload[1], 0x21);
    }

    #[test]
    fn main_sender_clears_the_retry_bit_of_an_odd_flow_id() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3345, 64);
        let packet = sender.send_payload(b"payload", ntp, now);
        let decoded = ReducedPacket::decode(&packet.bytes).unwrap();
        let rtp = RtpPacket::decode(decoded.payload).unwrap();
        assert_eq!(rtp.header.ssrc, 0x1122_3344);
        assert_eq!(sender.stats().flow_id, 0x1122_3344);
    }

    #[test]
    fn main_session_timers_schedule_keepalive_and_timeout() {
        let start = Instant::now();
        let mut timers = MainSessionTimers::with_config(MainSessionConfig {
            keepalive_interval: Duration::from_millis(10),
            session_timeout: Duration::from_millis(30),
        });

        assert_eq!(
            timers.poll(start),
            MainSessionPoll {
                keepalive_due: false,
                timed_out: false,
            }
        );
        assert!(timers.poll(start + Duration::from_millis(10)).keepalive_due);

        timers.observe_peer_activity(start + Duration::from_millis(15));
        assert!(!timers.poll(start + Duration::from_millis(44)).timed_out);
        assert!(timers.poll(start + Duration::from_millis(45)).timed_out);
    }

    #[test]
    fn main_profile_feedback_retransmits_original_rtp_sequence_in_new_gre_packet() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let first = sender.send_payload(b"first", ntp, now);
        let lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);

        receiver.accept_packet(&first.bytes).unwrap();
        let observed = receiver.accept_packet(&third.bytes).unwrap();
        assert_eq!(observed.newly_missing, vec![1]);

        let feedback = receiver.build_feedback();
        let feedback_decoded = ReducedPacket::decode(&feedback.bytes).unwrap();
        assert_eq!(feedback_decoded.reduced.src_port, DEFAULT_VIRT_DST_PORT);
        assert_eq!(feedback_decoded.reduced.dst_port, DEFAULT_VIRT_SRC_PORT);

        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].rtp_sequence, lost.rtp_sequence);
        assert_ne!(retries[0].gre_sequence, lost.gre_sequence);
        assert!(retries[0].retry);

        let recovered = receiver.accept_packet(&retries[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    #[test]
    fn main_profile_feedback_repairs_loss_after_rtp_sequence_wrap() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        sender.set_next_rtp_sequence(0xffff);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let first = sender.send_payload(b"first", ntp, now);
        let lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);

        receiver.accept_packet(&first.bytes).unwrap();
        let observed = receiver.accept_packet(&third.bytes).unwrap();
        assert_eq!(observed.newly_missing, vec![0x1_0000]);

        let feedback = receiver.build_feedback();
        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].rtp_sequence, lost.rtp_sequence);
        assert!(retries[0].retry);

        let recovered = receiver.accept_packet(&retries[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    #[test]
    fn main_profile_recovers_sustained_periodic_loss() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 256);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let mut lost_sequences = Vec::new();

        for index in 0..200u32 {
            let payload = index.to_be_bytes();
            let packet = sender.send_payload(&payload, ntp, now);
            if index % 10 == 3 {
                lost_sequences.push(packet.rtp_sequence);
            } else {
                receiver.accept_packet(&packet.bytes).unwrap();
            }
        }

        assert_eq!(receiver.missing_sequences(), lost_sequences);

        let feedback = receiver.build_feedback();
        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), lost_sequences.len());

        for retry in retries {
            let recovered = receiver.accept_packet(&retry.bytes).unwrap();
            assert!(recovered.recovered);
        }

        assert!(receiver.missing_sequences().is_empty());
        assert_eq!(
            receiver.stats().recovered_packets,
            lost_sequences.len() as u64
        );
    }

    #[test]
    fn main_poll_rtcp_all_sends_every_due_nack_packet_per_flow_in_flow_order() {
        let start = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver = MainReceiverCore::new(0x10, "rust", NackMode::Range)
            .with_recovery_tuning(RecoveryTuning {
                measure_rtt: false,
                ..RecoveryTuning::librist_like()
            });
        let mut senders =
            [0x30_u32, 0x10, 0x20].map(|ssrc| (ssrc, MainSenderCore::new(ssrc, 4096)));
        for (_, sender) in &mut senders {
            for index in 0..=1_000_u32 {
                let packet = sender.send_payload(&index.to_be_bytes(), ntp, start);
                if index % 2 == 0 {
                    receiver.accept_packet(&packet.bytes).unwrap();
                }
            }
        }
        assert_eq!(receiver.flow_ids(), vec![0x10, 0x20, 0x30]);
        // Every hole was detected after `start`: none is due yet.
        let now = start;
        assert!(receiver.poll_rtcp_all(now, ntp).is_empty());
        let due = receiver.poll_rtcp_all(Instant::now() + Duration::from_millis(20), ntp);
        // 500 isolated holes per flow: 3 packets of at most 200 records each.
        let flows = due.iter().map(|(flow_id, _)| *flow_id).collect::<Vec<_>>();
        assert_eq!(
            flows,
            vec![0x10, 0x10, 0x10, 0x20, 0x20, 0x20, 0x30, 0x30, 0x30]
        );
        for (ssrc, sender) in &mut senders {
            let mut retries = 0;
            let mut first = None;
            for (_, feedback) in due.iter().filter(|(flow_id, _)| flow_id == ssrc) {
                let packets = sender.handle_feedback(&feedback.bytes).unwrap();
                first.get_or_insert(packets[0].rtp_sequence);
                retries += packets.len();
            }
            assert_eq!(retries, 500, "flow {ssrc:#x}");
            assert_eq!(first, Some(1), "oldest hole first");
            let stats = receiver.stats_for_flow(*ssrc).unwrap();
            assert_eq!(stats.nack_packets, 3);
            assert_eq!(stats.nack_entries_sent, 500);
        }
    }

    #[test]
    fn main_poll_rtcp_all_with_stops_at_a_refused_send_and_keeps_holes_due() {
        let start = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver = MainReceiverCore::new(0x10, "rust", NackMode::Range)
            .with_recovery_tuning(RecoveryTuning {
                measure_rtt: false,
                ..RecoveryTuning::librist_like()
            });
        for ssrc in [0x10_u32, 0x20] {
            let mut sender = MainSenderCore::new(ssrc, 4096);
            for index in 0..=1_000_u32 {
                let packet = sender.send_payload(&index.to_be_bytes(), ntp, start);
                if index % 2 == 0 {
                    receiver.accept_packet(&packet.bytes).unwrap();
                }
            }
        }
        let now = start;
        assert!(receiver.poll_rtcp_all(now, ntp).is_empty());
        let first_poll = Instant::now() + Duration::from_millis(20);
        // Accept the first packet of flow 0x10, refuse the second.
        let mut offered = Vec::new();
        let accepted = receiver.poll_rtcp_all_with(first_poll, ntp, |flow_id, _| {
            offered.push(flow_id);
            offered.len() == 1
        });
        assert_eq!(accepted, 1);
        assert_eq!(offered, vec![0x10, 0x10], "nothing offered after a refusal");
        let stats = receiver.stats_for_flow(0x10).unwrap();
        assert_eq!(stats.nack_packets, 1);
        assert_eq!(stats.nack_entries_sent, 200);
        assert_eq!(stats.nack_entries_deferred, 300);
        assert_eq!(receiver.stats_for_flow(0x20).unwrap().nack_packets, 0);

        // The next poll requests the refused holes and the untouched flow.
        let due = receiver.poll_rtcp_all(first_poll + Duration::from_millis(20), ntp);
        let flows = due.iter().map(|(flow_id, _)| *flow_id).collect::<Vec<_>>();
        assert_eq!(flows, vec![0x10, 0x10, 0x10, 0x20, 0x20, 0x20]);
        assert_eq!(
            receiver.stats_for_flow(0x10).unwrap().nack_entries_sent,
            200 + 500
        );
        assert_eq!(
            receiver.stats_for_flow(0x20).unwrap().nack_entries_sent,
            500
        );
    }

    #[test]
    fn main_profile_normalizes_librist_retry_ssrc_bit() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let reduced = ReducedHeader {
            src_port: DEFAULT_VIRT_SRC_PORT,
            dst_port: DEFAULT_VIRT_DST_PORT,
        };

        let first = sender.prepare_payload(b"first", ntp, now);
        let lost = sender.prepare_payload(b"lost", ntp, now);
        let third = sender.prepare_payload(b"third", ntp, now);

        receiver.accept_reduced(reduced, &first.bytes).unwrap();
        let observed = receiver.accept_reduced(reduced, &third.bytes).unwrap();
        assert_eq!(observed.newly_missing, vec![1]);

        let mut retry = lost.bytes.clone();
        retry[11] |= 1;
        let recovered = receiver.accept_reduced(reduced, &retry).unwrap();

        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
        assert!(receiver.missing_sequences().is_empty());
        assert_eq!(receiver.stats().recovered_packets, 1);
    }

    #[test]
    fn main_sender_answers_echo_request_through_reduced_gre() {
        let now = Instant::now();
        let request_ntp = ntp_from_unix_duration(Duration::from_secs(9));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut request = Vec::new();
        crate::packet::rtcp::encode_empty_receiver_report(0x1122_3344, &mut request);
        crate::packet::rtcp::encode_echo(
            Echo {
                ssrc: 0x1122_3344,
                ntp_timestamp: request_ntp,
                kind: EchoKind::Request,
            },
            &mut request,
        );
        let reduced = ReducedHeader {
            src_port: DEFAULT_VIRT_DST_PORT,
            dst_port: DEFAULT_VIRT_SRC_PORT,
        };
        let outcome = sender
            .handle_reduced_feedback_outcome(reduced, &request, request_ntp, now)
            .unwrap();
        assert!(outcome.retries.is_empty());
        assert_eq!(outcome.responses.len(), 1);
        let decoded = ReducedPacket::decode(&outcome.responses[0].bytes).unwrap();
        assert_eq!(decoded.reduced.src_port, DEFAULT_VIRT_SRC_PORT);
        assert!(decode_compound(decoded.payload)
            .unwrap()
            .contains(&RtcpPacket::Echo(Echo {
                ssrc: 0x1122_3344,
                ntp_timestamp: request_ntp,
                kind: EchoKind::Response { delay: 0 },
            })));
    }

    #[test]
    fn main_duplicate_repairs_are_wrapped_and_marked() {
        let t = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let first = sender.send_payload(b"first", ntp, t);
        let _lost = sender.send_payload(b"lost", ntp, t);
        let third = sender.send_payload(b"third", ntp, t);
        receiver.accept_packet(&first.bytes).unwrap();
        receiver.accept_packet(&third.bytes).unwrap();
        // The first packet goes out twice: the copy is wrapped and marked,
        // and a receiver that has the original drops it.
        assert_eq!(sender.next_repair_at(), Some(t + Duration::from_millis(1)));
        let startup = sender.poll_repairs(t + Duration::from_millis(1));
        assert_eq!(startup.len(), 1);
        assert!(startup[0].retry);
        assert!(receiver.accept_packet(&startup[0].bytes).unwrap().duplicate);
        let feedback = receiver.build_feedback();
        let reduced = ReducedHeader {
            src_port: DEFAULT_VIRT_DST_PORT,
            dst_port: DEFAULT_VIRT_SRC_PORT,
        };
        let payload = ReducedPacket::decode(&feedback.bytes)
            .unwrap()
            .payload
            .to_vec();
        for at in [t, t + Duration::from_millis(10)] {
            let outcome = sender
                .handle_reduced_feedback_outcome(reduced, &payload, ntp, at)
                .unwrap();
            assert_eq!(outcome.retries.len(), 1);
        }
        let due = sender.next_repair_at().unwrap();
        let copies = sender.poll_repairs(due);
        assert_eq!(copies.len(), 1);
        assert!(copies[0].retry);
        let decoded = ReducedPacket::decode(&copies[0].bytes).unwrap();
        assert_eq!(
            RtpPacket::decode(decoded.payload).unwrap().header.ssrc,
            0x1122_3345
        );
        let recovered = receiver.accept_packet(&copies[0].bytes).unwrap();
        assert!(recovered.recovered);
    }

    #[test]
    fn main_retransmission_carries_the_retry_bit_and_round_trips() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let first = sender.send_payload(b"first", ntp, now);
        let _lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);
        receiver.accept_packet(&first.bytes).unwrap();
        receiver.accept_packet(&third.bytes).unwrap();

        let feedback = receiver.build_feedback();
        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), 1);
        let decoded = ReducedPacket::decode(&retries[0].bytes).unwrap();
        let rtp = RtpPacket::decode(decoded.payload).unwrap();
        assert_eq!(rtp.header.ssrc, 0x1122_3345, "retries are marked SSRC | 1");

        let recovered = receiver.accept_packet(&retries[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert_eq!(receiver.flow_ids(), vec![0x1122_3344]);
        assert_eq!(receiver.stats().retry_packets_received, 1);
    }

    #[test]
    fn main_profile_preserves_npd_through_gre() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64).with_null_packet_suppression(true);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);

        let mut payload = Vec::new();
        payload.extend_from_slice(&ts_packet(0x0100, b"first"));
        payload.extend_from_slice(&ts_packet(TS_NULL_PID, b""));
        payload.extend_from_slice(&ts_packet(0x0101, b"third"));

        let packet = sender.send_payload(&payload, ntp, now);
        let reduced = ReducedPacket::decode(&packet.bytes).unwrap();
        let rtp = RtpPacket::decode(reduced.payload).unwrap();
        assert!(rtp.extension.is_some());
        assert_eq!(rtp.payload.len(), TS_PACKET_SIZE * 2);

        let received = receiver.accept_packet(&packet.bytes).unwrap();
        assert_eq!(received.payload, payload);
    }

    #[test]
    fn sender_control_packets_share_gre_sequence_space() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);

        let data = sender.send_payload(b"payload", ntp, now);
        let keepalive = sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let negotiation = sender.build_buffer_negotiation(BufferNegotiation::session(1000, 250));

        assert_eq!(data.gre_sequence, 0);
        assert_eq!(keepalive.gre_sequence, 1);
        assert_eq!(negotiation.gre_sequence, 2);

        let decoded_keepalive = KeepalivePacket::decode(&keepalive.bytes).unwrap();
        assert_eq!(
            decoded_keepalive.gre.protocol_type,
            GRE_PROTOCOL_TYPE_KEEPALIVE
        );
        assert_eq!(decoded_keepalive.gre.sequence, Some(1));
        assert_eq!(decoded_keepalive.gre.version, 1);
        assert_eq!(decoded_keepalive.keepalive.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(
            decoded_keepalive.keepalive.capabilities1 & KEEPALIVE_CAP1_NULL_PACKET_DELETION,
            KEEPALIVE_CAP1_NULL_PACKET_DELETION
        );
        assert_eq!(
            decoded_keepalive.keepalive.capabilities2 & KEEPALIVE_CAP2_REDUCED_OVERHEAD,
            KEEPALIVE_CAP2_REDUCED_OVERHEAD
        );

        let decoded_negotiation = BufferNegotiationPacket::decode(&negotiation.bytes).unwrap();
        assert_eq!(decoded_negotiation.gre.sequence, Some(2));
        assert_eq!(decoded_negotiation.negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(
            decoded_negotiation.negotiation.receiver_current_buffer_ms,
            250
        );
    }

    #[test]
    fn sender_gre_negotiation_only_upgrades_the_version() {
        let mut sender = MainSenderCore::new(0x1122_3344, 64);

        sender.upgrade_gre_version(2);
        sender.upgrade_gre_version(1);

        let keepalive = sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let decoded = KeepalivePacket::decode(&keepalive.bytes).unwrap();
        assert_eq!(decoded.gre.version, 2);
    }

    #[test]
    fn sender_polls_scheduled_rtcp_over_reduced_gre() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);

        assert_eq!(sender.poll_rtcp(now, ntp), None);
        let control = sender.poll_rtcp(now + Duration::from_secs(1), ntp).unwrap();

        assert_eq!(control.gre_sequence, 0);
        let reduced = ReducedPacket::decode(&control.bytes).unwrap();
        assert_eq!(reduced.reduced.src_port, DEFAULT_VIRT_SRC_PORT);
        assert_eq!(reduced.reduced.dst_port, DEFAULT_VIRT_DST_PORT);
        assert_eq!(
            decode_compound(reduced.payload).unwrap(),
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
    fn receiver_accepts_main_control_packets() {
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let keepalive = sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let negotiation = sender.build_buffer_negotiation(BufferNegotiation::session(1000, 250));

        let keepalive = receiver.accept_keepalive(&keepalive.bytes).unwrap();
        assert!(keepalive.keepalive.supports_null_packet_deletion());
        let negotiation = receiver
            .accept_buffer_negotiation(&negotiation.bytes)
            .unwrap();
        assert_eq!(negotiation.negotiation.receiver_current_buffer_ms, 250);
    }

    #[test]
    fn main_profile_encrypts_and_decrypts_control_packets() {
        let sender_tx = PskKey::new(256, b"secret").unwrap();
        let receiver_rx = PskKey::receiver(256, b"secret").unwrap();
        let mut sender = MainSenderCore::new(0x1122_3344, 64).with_tx_key(sender_tx);
        let mut receiver =
            MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range).with_rx_key(receiver_rx);

        let keepalive = sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let keepalive_header = GreHeader::decode(&keepalive.bytes).unwrap().0;
        assert!(keepalive_header.key.is_some());
        assert!(KeepalivePacket::decode(&keepalive.bytes).is_err());
        let keepalive = receiver.accept_keepalive(&keepalive.bytes).unwrap();
        assert_eq!(keepalive.keepalive.mac, [1, 2, 3, 4, 5, 6]);
        assert!(keepalive.keepalive.supports_reduced_overhead());

        let negotiation = sender.build_buffer_negotiation(BufferNegotiation::session(1000, 250));
        let negotiation_header = GreHeader::decode(&negotiation.bytes).unwrap().0;
        assert!(negotiation_header.key.is_some());
        assert!(BufferNegotiationPacket::decode(&negotiation.bytes).is_err());
        let negotiation = receiver
            .accept_buffer_negotiation(&negotiation.bytes)
            .unwrap();
        assert_eq!(negotiation.negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(negotiation.negotiation.receiver_current_buffer_ms, 250);
    }

    #[test]
    fn main_profile_sends_eapol_control_packets_in_clear() {
        let sender_tx = PskKey::new(256, b"secret").unwrap();
        let receiver_rx = PskKey::receiver(256, b"secret").unwrap();
        let mut sender = MainSenderCore::new(0x1122_3344, 64).with_tx_key(sender_tx);
        let mut receiver =
            MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range).with_rx_key(receiver_rx);
        let frame =
            EapolFrame::eap(EAPOL_VERSION_3, &EapPacket::identity_response(3, b"rist")).unwrap();

        let packet = sender.build_eapol(&frame).unwrap();
        let header = GreHeader::decode(&packet.bytes).unwrap().0;
        assert_eq!(
            header.protocol_type,
            crate::packet::gre::GRE_PROTOCOL_TYPE_EAPOL
        );
        assert!(header.key.is_none());

        let accepted = receiver.accept_eapol(&packet.bytes).unwrap();
        assert_eq!(accepted.eap_packet().unwrap().data, b"rist");
    }

    #[test]
    fn main_profile_encrypts_and_decrypts_payload() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let tx_key = PskKey::new(256, b"secret").unwrap();
        let rx_key = PskKey::receiver(256, b"secret").unwrap();
        let mut sender = MainSenderCore::new(0x1122_3344, 64).with_tx_key(tx_key);
        let mut receiver =
            MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range).with_rx_key(rx_key);

        let packet = sender.send_payload(b"payload", ntp, now);
        assert!(GreHeader::decode(&packet.bytes).unwrap().0.key.is_some());
        assert!(ReducedPacket::decode(&packet.bytes).is_err());

        let received = receiver.accept_packet(&packet.bytes).unwrap();
        assert_eq!(received.payload, b"payload");
    }

    #[test]
    fn main_profile_recovers_over_encrypted_feedback() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let sender_tx = PskKey::new(256, b"secret").unwrap();
        let sender_rx = PskKey::receiver(256, b"secret").unwrap();
        let receiver_tx = PskKey::new(256, b"secret").unwrap();
        let receiver_rx = PskKey::receiver(256, b"secret").unwrap();
        let mut sender = MainSenderCore::new(0x1122_3344, 64)
            .with_tx_key(sender_tx)
            .with_rx_key(sender_rx);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_tx_key(receiver_tx)
            .with_rx_key(receiver_rx);

        let first = sender.send_payload(b"first", ntp, now);
        let lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);

        receiver.accept_packet(&first.bytes).unwrap();
        let observed = receiver.accept_packet(&third.bytes).unwrap();
        assert_eq!(observed.newly_missing, vec![1]);

        let feedback = receiver.build_feedback();
        assert_eq!(&feedback.bytes[..4], &[0x30, 0x48, 0x88, 0xb6]);
        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].rtp_sequence, lost.rtp_sequence);

        let recovered = receiver.accept_packet(&retries[0].bytes).unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    /// A Main receiver with a key drops clear data, RTCP, keepalives and
    /// buffer negotiation on every entry point, counts them, delivers
    /// nothing, and still takes EAPOL in clear.
    #[test]
    fn keyed_main_receiver_drops_clear_packets_on_every_entry_point() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut clear_sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());

        // The first poll arms the report timer.
        assert_eq!(clear_sender.poll_rtcp(now, ntp), None);
        let rtcp = clear_sender
            .poll_rtcp(now + Duration::from_secs(1), ntp)
            .unwrap();
        let data = clear_sender.send_payload(b"clear", ntp, now + Duration::from_secs(1));
        let keepalive =
            clear_sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let negotiation =
            clear_sender.build_buffer_negotiation(BufferNegotiation::session(1000, 0));

        let clear = crate::Error::ClearPacketWithPsk;
        assert_eq!(receiver.accept_packet(&data.bytes).unwrap_err(), clear);
        assert_eq!(receiver.decode_datagram(&data.bytes).unwrap_err(), clear);
        assert_eq!(receiver.handle_rtcp(&rtcp.bytes, ntp).unwrap_err(), clear);
        assert_eq!(receiver.decode_datagram(&rtcp.bytes).unwrap_err(), clear);
        assert_eq!(
            receiver.accept_keepalive(&keepalive.bytes).unwrap_err(),
            clear
        );
        assert_eq!(
            receiver.decode_datagram(&keepalive.bytes).unwrap_err(),
            clear
        );
        assert_eq!(
            receiver
                .accept_buffer_negotiation(&negotiation.bytes)
                .unwrap_err(),
            clear
        );
        assert_eq!(
            receiver.screen_clear_datagram(&data.bytes).unwrap_err(),
            clear
        );

        let stats = receiver.stats();
        assert_eq!(stats.clear_packets_dropped, 8);
        assert_eq!(stats.received_packets, 0);
        assert_eq!(stats.decrypt_rejected, 0);
        assert_eq!(receiver.flow_count(), 1);

        let frame =
            EapolFrame::eap(EAPOL_VERSION_3, &EapPacket::identity_response(3, b"rist")).unwrap();
        let eapol = clear_sender.build_eapol(&frame).unwrap();
        receiver.screen_clear_datagram(&eapol.bytes).unwrap();
        assert!(matches!(
            receiver.decode_datagram(&eapol.bytes).unwrap(),
            MainPacket::Eapol(_)
        ));
        assert_eq!(receiver.accept_eapol(&eapol.bytes).unwrap(), frame);
        assert_eq!(receiver.stats().clear_packets_dropped, 8);

        // A fresh session for a new source starts its counters at zero.
        assert_eq!(receiver.fresh_session().stats().clear_packets_dropped, 0);
    }

    /// A keyed receive session is proven only by checked data or RTCP: a
    /// forged keepalive from a host with no key (which decrypts to
    /// something that passes the keepalive check every time) and the
    /// peer's own keepalives leave it unproven.
    #[test]
    fn keyed_receive_session_is_proven_only_by_data_or_rtcp() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let template = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        assert!(MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range).rx_peer_proven());

        // GRE K and S, keepalive protocol, a fixed nonce, eight junk bytes.
        let mut forged = vec![0x30, 0x00, 0x88, 0xb5, 0x0b, 0xad, 0x00, 0x01];
        forged.extend_from_slice(&7u32.to_be_bytes());
        forged.extend_from_slice(&[0x5a; 8]);
        let mut attacker = template.fresh_session();
        for _ in 0..100 {
            assert!(matches!(
                attacker.decode_datagram(&forged).unwrap(),
                MainPacket::Keepalive(_)
            ));
        }
        assert!(!attacker.rx_peer_proven());

        let mut sender =
            MainSenderCore::new(0x1122_3344, 64).with_tx_key(PskKey::new(128, b"secret").unwrap());
        let mut session = template.fresh_session();
        let keepalive = sender.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        let negotiation = sender.build_buffer_negotiation(BufferNegotiation::session(1000, 0));
        assert!(matches!(
            session.decode_datagram(&keepalive.bytes).unwrap(),
            MainPacket::Keepalive(_)
        ));
        assert!(matches!(
            session.decode_datagram(&negotiation.bytes).unwrap(),
            MainPacket::BufferNegotiation(_)
        ));
        assert!(!session.rx_peer_proven());
        let data = sender.send_payload(b"payload", ntp, now);
        assert!(matches!(
            session.decode_datagram(&data.bytes).unwrap(),
            MainPacket::Reduced(_)
        ));
        assert!(session.rx_peer_proven());

        // RTCP proves a session as well.
        let mut rtcp_session = template.fresh_session();
        assert_eq!(sender.poll_rtcp(now, ntp), None);
        let rtcp = sender.poll_rtcp(now + Duration::from_secs(1), ntp).unwrap();
        rtcp_session.decode_datagram(&rtcp.bytes).unwrap();
        assert!(rtcp_session.rx_peer_proven());
    }

    /// A keyed Main sender takes no clear feedback: a clear NACK is
    /// dropped and counted, and nothing is retransmitted for it.
    #[test]
    fn keyed_main_sender_drops_clear_feedback() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64)
            .with_tx_key(PskKey::new(128, b"secret").unwrap())
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let mut clear_receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let first = sender.send_payload(b"first", ntp, now);
        let _lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);
        clear_receiver.accept_packet(&first.bytes).unwrap();
        clear_receiver.accept_packet(&third.bytes).unwrap();
        // A NACK with the same content, sent clear.
        let nack =
            crate::packet::rtcp::encode_nack_compound(NackMode::Range, 0x1122_3344, "rust", &[1]);
        let clear_nack = crate::packet::gre::encode_reduced_payload(
            1,
            0,
            ReducedHeader {
                src_port: DEFAULT_VIRT_DST_PORT,
                dst_port: DEFAULT_VIRT_SRC_PORT,
            },
            &nack,
        );
        assert_eq!(
            sender.handle_feedback(&clear_nack).unwrap_err(),
            crate::Error::ClearPacketWithPsk
        );
        assert_eq!(
            sender.decode_datagram(&clear_nack).unwrap_err(),
            crate::Error::ClearPacketWithPsk
        );
        let stats = sender.stats();
        assert_eq!(stats.clear_packets_dropped, 2);
        assert_eq!(stats.retransmitted_packets, 0);

        let mut peer = sender.new_peer_state();
        assert_eq!(
            sender
                .handle_feedback_for_peer(&mut peer, &clear_nack)
                .unwrap_err(),
            crate::Error::ClearPacketWithPsk
        );
        assert_eq!(peer.stats().clear_packets_dropped, 1);
    }

    /// An endpoint given only a receive key encrypts what it sends with
    /// the same passphrase: a receiver's NACKs, reports and keepalives,
    /// and a sender's data, are never clear.
    #[test]
    fn receive_key_alone_makes_an_endpoint_send_encrypted() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let first = sender.send_payload(b"first", ntp, now);
        let _lost = sender.send_payload(b"lost", ntp, now);
        let third = sender.send_payload(b"third", ntp, now);
        for packet in [&first, &third] {
            assert!(GreHeader::decode(&packet.bytes).unwrap().0.key.is_some());
            receiver.accept_packet(&packet.bytes).unwrap();
        }
        let feedback = receiver.build_feedback();
        let keepalive = receiver.build_keepalive(GreKeepalive::librist_default([1; 6]));
        let negotiation = receiver.build_buffer_negotiation(BufferNegotiation::session(0, 500));
        let oob = receiver.build_oob(b"oob");
        for bytes in [
            &feedback.bytes,
            &keepalive.bytes,
            &negotiation.bytes,
            &oob.bytes,
        ] {
            assert!(GreHeader::decode(bytes).unwrap().0.key.is_some());
        }
        let retries = sender.handle_feedback(&feedback.bytes).unwrap();
        assert_eq!(retries.len(), 1);
        assert!(GreHeader::decode(&retries[0].bytes)
            .unwrap()
            .0
            .key
            .is_some());
        assert!(receiver.accept_packet(&retries[0].bytes).unwrap().recovered);
        assert_eq!(receiver.stats().decrypt_rejected, 0);
        assert_eq!(sender.stats().decrypt_rejected, 0);
    }

    /// An endpoint given only a transmit key drops clear packets from its
    /// peer: a sender takes no clear NACK, a receiver no clear data.
    #[test]
    fn transmit_key_alone_makes_an_endpoint_drop_clear_packets() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut clear_sender = MainSenderCore::new(0x1122_3344, 64);
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_tx_key(PskKey::new(128, b"secret").unwrap());
        let data = clear_sender.send_payload(b"clear", ntp, now);
        assert_eq!(
            receiver.accept_packet(&data.bytes).unwrap_err(),
            crate::Error::ClearPacketWithPsk
        );
        let mut sender =
            MainSenderCore::new(0x1122_3344, 64).with_tx_key(PskKey::new(128, b"secret").unwrap());
        let mut clear_receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
        let first = clear_sender.send_payload(b"a", ntp, now);
        clear_receiver.accept_packet(&first.bytes).unwrap();
        let report = clear_receiver.build_feedback();
        assert_eq!(
            sender.handle_feedback(&report.bytes).unwrap_err(),
            crate::Error::ClearPacketWithPsk
        );
        assert_eq!(receiver.stats().clear_packets_dropped, 1);
        assert_eq!(sender.stats().clear_packets_dropped, 1);
        // And what the receiver sends is still encrypted.
        let keepalive = receiver.build_keepalive(GreKeepalive::librist_default([1; 6]));
        assert!(GreHeader::decode(&keepalive.bytes).unwrap().0.key.is_some());
    }

    /// A receiver keyed with the wrong passphrase delivers nothing from an
    /// encrypted sender and counts the rejection; the nonce is shut out
    /// after its first failure, so later packets are not even decrypted.
    #[test]
    fn wrong_passphrase_receiver_delivers_nothing_and_counts() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender =
            MainSenderCore::new(0x1122_3344, 64).with_tx_key(PskKey::new(128, b"right").unwrap());
        let mut receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"wrong").unwrap());
        let mut payload = Vec::new();
        for pid in 0x100..0x107 {
            payload.extend_from_slice(&ts_packet(pid, b"wrong secret"));
        }
        for _ in 0..50 {
            let packet = sender.send_payload(&payload, ntp, now);
            assert!(receiver.accept_packet(&packet.bytes).is_err());
        }
        let stats = receiver.stats();
        assert_eq!(stats.received_packets, 0);
        assert_eq!(stats.decrypt_rejected, 1);
        assert_eq!(stats.decrypt_latched, 49);
        assert_eq!(stats.nonce_latches, 1);
        assert_eq!(receiver.flow_count(), 1);
    }

    fn ts_packet(pid: u16, label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xff; TS_PACKET_SIZE];
        packet[0] = TS_SYNC_BYTE;
        packet[1..3].copy_from_slice(&pid.to_be_bytes());
        packet[3] = 0x10;
        packet[4..4 + label.len()].copy_from_slice(label);
        packet
    }

    fn gre_nonce(datagram: &[u8]) -> ([u8; 4], u32) {
        let (gre, _) = GreHeader::decode(datagram).unwrap();
        (
            gre.key.expect("encrypted").to_be_bytes(),
            gre.sequence.expect("encrypted"),
        )
    }

    /// Each peer state of a keyed sender encrypts with its own nonce:
    /// peers' GRE sequences each start at 0, so a shared nonce would put
    /// different packets under one AES-CTR keystream. A receiver with the
    /// passphrase decrypts every peer's packets.
    #[test]
    fn sender_peer_states_get_their_own_transmit_nonce() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender =
            MainSenderCore::new(0x1122_3344, 64).with_tx_key(PskKey::new(128, b"secret").unwrap());
        let mut peer_a = sender.new_peer_state();
        let mut peer_b = sender.new_peer_state();
        let core_nonce = sender.tx_key.as_ref().unwrap().nonce();
        let nonce_a = peer_a.tx_key.as_ref().unwrap().nonce();
        let nonce_b = peer_b.tx_key.as_ref().unwrap().nonce();
        assert_ne!(nonce_a, nonce_b);
        assert_ne!(nonce_a, core_nonce);
        assert_ne!(nonce_b, core_nonce);

        // Different packets to each peer at the same GRE sequence (what a
        // weighted multi-sender does): different nonces on the wire, and
        // the ciphertext XOR is not the plaintext XOR.
        let packet_a = sender.prepare_payload(&[0x47; 188], ntp, now);
        let packet_b = sender.prepare_payload(&[0x11; 188], ntp, now);
        let wire_a = sender.wrap_payload_for_peer(&mut peer_a, &packet_a);
        let wire_b = sender.wrap_payload_for_peer(&mut peer_b, &packet_b);
        let (wire_nonce_a, seq_a) = gre_nonce(&wire_a.bytes);
        let (wire_nonce_b, seq_b) = gre_nonce(&wire_b.bytes);
        assert_eq!(seq_a, seq_b);
        assert_eq!((wire_nonce_a, wire_nonce_b), (nonce_a, nonce_b));
        for wire in [&wire_a.bytes, &wire_b.bytes] {
            let mut receiver = MainReceiverCore::new(0x1122_3344, "rx", NackMode::Range)
                .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
            assert!(matches!(
                receiver.decode_datagram(wire).unwrap(),
                MainPacket::Reduced(_)
            ));
            assert_eq!(receiver.stats().decrypt_rejected, 0);
        }
    }

    /// Each receiver session encrypts its NACKs and reports with its own
    /// nonce, whether the receiver was given a transmit key or only a
    /// receive key.
    #[test]
    fn receiver_sessions_get_their_own_transmit_nonce() {
        let with_tx = MainReceiverCore::new(0x1122_3344, "rx", NackMode::Range)
            .with_tx_key(PskKey::new(128, b"secret").unwrap())
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let rx_only = MainReceiverCore::new(0x1122_3344, "rx", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        for template in [with_tx, rx_only] {
            let template_nonce = template.tx_key.as_ref().unwrap().nonce();
            let mut a = template.fresh_session();
            let mut b = template.fresh_session();
            let nonce_a = a.tx_key.as_ref().unwrap().nonce();
            let nonce_b = b.tx_key.as_ref().unwrap().nonce();
            assert_ne!(nonce_a, nonce_b);
            assert_ne!(nonce_a, template_nonce);
            assert_ne!(nonce_b, template_nonce);
            let feedback_a = a.build_feedback();
            let feedback_b = b.build_feedback();
            let (wire_a, seq_a) = gre_nonce(&feedback_a.bytes);
            let (wire_b, seq_b) = gre_nonce(&feedback_b.bytes);
            assert_eq!(seq_a, seq_b);
            assert_ne!(wire_a, wire_b);
        }
    }

    /// Review 3, defect 2: a new receiver session or sender peer state picks
    /// its own transmit nonce but derives no AES key (PBKDF2) until it first
    /// sends, so sessions that a flood of forged packets creates cost no
    /// derivation outside the receive-wide budget.
    #[test]
    fn new_sessions_and_peer_states_derive_no_key_until_they_send() {
        let with_tx = MainReceiverCore::new(0x1122_3344, "rx", NackMode::Range)
            .with_tx_key(PskKey::new(128, b"secret").unwrap())
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let rx_only = MainReceiverCore::new(0x1122_3344, "rx", NackMode::Range)
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        for template in [with_tx, rx_only] {
            let mut session = template.fresh_session();
            assert!(!session.tx_key.as_ref().unwrap().aes_key_derived());
            assert!(!session.rx_key.as_ref().unwrap().aes_key_derived());
            let nonce = session.tx_key.as_ref().unwrap().nonce();
            assert_ne!(nonce, [0; 4]);
            let feedback = session.build_feedback();
            assert_eq!(gre_nonce(&feedback.bytes).0, nonce);
            assert!(session.tx_key.as_ref().unwrap().aes_key_derived());
        }

        let sender = MainSenderCore::new(0x1122_3344, 64)
            .with_tx_key(PskKey::new(128, b"secret").unwrap())
            .with_rx_key(PskKey::receiver(128, b"secret").unwrap());
        let state = sender.new_peer_state();
        assert!(!state.tx_key.as_ref().unwrap().aes_key_derived());
        assert!(!state.rx_key.as_ref().unwrap().aes_key_derived());
    }
}
