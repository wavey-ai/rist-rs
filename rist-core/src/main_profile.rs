use crate::auth::EapolFrame;
use crate::crypto::PskKey;
use crate::endpoint::{CongestionControlMode, RecoveryConfig};
use crate::packet::gre::{
    decode_eapol_payload, decode_encrypted_buffer_negotiation_packet,
    decode_encrypted_keepalive_packet, decode_encrypted_reduced_packet, decode_main_packet,
    encode_buffer_negotiation_payload, encode_eapol_payload,
    encode_encrypted_buffer_negotiation_payload, encode_encrypted_keepalive_payload,
    encode_encrypted_oob_payload, encode_encrypted_reduced_payload, encode_keepalive_payload,
    encode_oob_payload, encode_reduced_payload, BufferNegotiation, BufferNegotiationPacket,
    GreHeader, GreKeepalive, KeepalivePacket, MainPacket, OwnedBufferNegotiationPacket,
    OwnedKeepalivePacket, OwnedReducedPacket, ReducedHeader, ReducedPacket,
};
use crate::packet::rtcp::NackMode;
use crate::packet::rtp::RtpPacket;
use crate::simple::{
    OutboundPacket, ReceivedPayload, SimpleReceiverCore, SimpleSenderCore, SimpleSenderPeerState,
};
use crate::stats::{ReceiverStats, SenderStats};
use crate::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainOutboundPacket {
    pub rtp_sequence: u32,
    pub gre_sequence: u32,
    pub retry: bool,
    pub bytes: Vec<u8>,
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
        self.simple.stats()
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.tx_key = Some(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
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

    pub fn with_gre_version(mut self, gre_version: u8) -> Self {
        self.gre_version = gre_version;
        self
    }

    pub fn with_null_packet_suppression(mut self, enabled: bool) -> Self {
        self.simple = self.simple.with_null_packet_suppression(enabled);
        self
    }

    pub fn with_tx_key(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key);
        self
    }

    pub fn with_rx_key(mut self, key: PskKey) -> Self {
        self.rx_key = Some(key);
        self
    }

    pub fn with_psk(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key.clone());
        self.rx_key = Some(key);
        self
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.tx_key = Some(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
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
        let packet = self.prepare_payload(payload, ntp_timestamp, now);
        self.wrap_rtp(packet.sequence, packet.retry, &packet.bytes)
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
            tx_key: self.tx_key.clone(),
            rx_key: self.rx_key.clone(),
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

    pub fn handle_reduced_feedback(
        &mut self,
        _reduced: ReducedHeader,
        payload: &[u8],
    ) -> Result<Vec<MainOutboundPacket>> {
        let retries = self.simple.handle_feedback(payload)?;
        Ok(retries
            .into_iter()
            .map(|retry| self.wrap_rtp(retry.sequence, true, &retry.bytes))
            .collect())
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
        let retries = self
            .simple
            .handle_feedback_for_peer(&mut state.simple, payload)?;
        Ok(retries
            .into_iter()
            .map(|retry| self.wrap_rtp_for_peer(state, retry.sequence, true, &retry.bytes))
            .collect())
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
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return decode_encrypted_keepalive_packet(packet, key);
        }
        Ok(KeepalivePacket::decode(packet)?.into_owned())
    }

    pub fn accept_buffer_negotiation(
        &mut self,
        packet: &[u8],
    ) -> Result<OwnedBufferNegotiationPacket> {
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return decode_encrypted_buffer_negotiation_packet(packet, key);
        }
        Ok(BufferNegotiationPacket::decode(packet)?.into_owned())
    }

    pub fn accept_eapol(&mut self, packet: &[u8]) -> Result<EapolFrame> {
        Ok(decode_eapol_payload(packet)?.frame)
    }

    pub fn decode_datagram(&mut self, packet: &[u8]) -> Result<MainPacket> {
        decode_main_packet(packet, self.rx_key.as_mut())
    }

    pub fn stats(&self) -> SenderStats {
        self.simple.stats()
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
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return Ok(DecodedReduced::Owned(decode_encrypted_reduced_packet(
                packet, key,
            )?));
        }
        Ok(DecodedReduced::Borrowed(ReducedPacket::decode(packet)?))
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
    let (gre, _) = GreHeader::decode(packet)?;
    if gre.key.is_some() {
        let Some(key) = &mut state.rx_key else {
            return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
        };
        return Ok(DecodedReduced::Owned(decode_encrypted_reduced_packet(
            packet, key,
        )?));
    }
    Ok(DecodedReduced::Borrowed(ReducedPacket::decode(packet)?))
}

#[derive(Debug, Clone)]
pub struct MainReceiverCore {
    primary_flow_id: u32,
    cname: String,
    nack_mode: NackMode,
    flows: HashMap<u32, SimpleReceiverCore>,
    max_flows: usize,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
    gre_version: u8,
    next_gre_sequence: u32,
    last_reduced: Option<ReducedHeader>,
    flow_reduced: HashMap<u32, ReducedHeader>,
    tx_key: Option<PskKey>,
    rx_key: Option<PskKey>,
}

impl MainReceiverCore {
    pub fn new(flow_id: u32, cname: impl Into<String>, nack_mode: NackMode) -> Self {
        let cname = cname.into();
        let mut flows = HashMap::new();
        flows.insert(
            flow_id,
            SimpleReceiverCore::new(flow_id, cname.clone(), nack_mode),
        );
        Self {
            primary_flow_id: flow_id,
            cname,
            nack_mode,
            flows,
            max_flows: DEFAULT_MAIN_FLOWS_PER_PEER,
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
            gre_version: 1,
            next_gre_sequence: 0,
            last_reduced: None,
            flow_reduced: HashMap::new(),
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

    pub fn with_tx_key(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key);
        self
    }

    pub fn with_rx_key(mut self, key: PskKey) -> Self {
        self.rx_key = Some(key);
        self
    }

    pub fn with_psk(mut self, key: PskKey) -> Self {
        self.tx_key = Some(key.clone());
        self.rx_key = Some(key);
        self
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.tx_key = Some(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
        self.rx_key = Some(key);
    }

    pub fn decode_datagram(&mut self, packet: &[u8]) -> Result<MainPacket> {
        decode_main_packet(packet, self.rx_key.as_mut())
    }

    pub fn fresh_session(&self) -> Self {
        let mut session = Self::new(self.primary_flow_id, self.cname.clone(), self.nack_mode)
            .with_gre_version(self.gre_version);
        session.set_recovery_config(self.recovery.clone(), self.congestion_control);
        session.max_flows = self.max_flows;
        if let Some(key) = &self.tx_key {
            session.set_tx_key(key.clone());
        }
        if let Some(key) = &self.rx_key {
            session.set_rx_key(key.clone());
        }
        session
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
        self.last_reduced = Some(reduced);
        let packet = RtpPacket::decode(payload)?;
        let flow_id = packet.header.ssrc & !1;
        self.flow_reduced.insert(flow_id, reduced);
        self.flow_mut(flow_id)?.accept_rtp_packet(packet)
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
        let flow_ids = self.flow_ids();
        let mut due = Vec::new();
        for flow_id in flow_ids {
            if let Some(packet) = self
                .flows
                .get_mut(&flow_id)
                .expect("listed Main receiver flow must exist")
                .poll_rtcp(now, now_ntp)
            {
                due.push((flow_id, packet));
            }
        }
        due.into_iter()
            .map(|(flow_id, packet)| {
                (
                    flow_id,
                    self.wrap_feedback_payload_for_flow(flow_id, &packet),
                )
            })
            .collect()
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
        let reduced = self
            .last_reduced
            .map(|reduced| ReducedHeader {
                src_port: reduced.dst_port,
                dst_port: reduced.src_port,
            })
            .unwrap_or(ReducedHeader {
                src_port: DEFAULT_VIRT_DST_PORT,
                dst_port: DEFAULT_VIRT_SRC_PORT,
            });
        self.wrap_feedback_with_reduced(reduced, feedback)
    }

    fn wrap_feedback_payload_for_flow(
        &mut self,
        flow_id: u32,
        feedback: &[u8],
    ) -> MainReceiverFeedback {
        let reduced = self
            .flow_reduced
            .get(&flow_id)
            .copied()
            .map(|reduced| ReducedHeader {
                src_port: reduced.dst_port,
                dst_port: reduced.src_port,
            })
            .unwrap_or(ReducedHeader {
                src_port: DEFAULT_VIRT_DST_PORT,
                dst_port: DEFAULT_VIRT_SRC_PORT,
            });
        self.wrap_feedback_with_reduced(reduced, feedback)
    }

    fn wrap_feedback_with_reduced(
        &mut self,
        reduced: ReducedHeader,
        feedback: &[u8],
    ) -> MainReceiverFeedback {
        let gre_sequence = self.next_gre_sequence();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_reduced_payload(self.gre_version, gre_sequence, reduced, feedback, key)
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, feedback)
        };
        MainReceiverFeedback {
            gre_sequence,
            bytes,
        }
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
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return decode_encrypted_keepalive_packet(packet, key);
        }
        Ok(KeepalivePacket::decode(packet)?.into_owned())
    }

    pub fn accept_buffer_negotiation(
        &mut self,
        packet: &[u8],
    ) -> Result<OwnedBufferNegotiationPacket> {
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return decode_encrypted_buffer_negotiation_packet(packet, key);
        }
        Ok(BufferNegotiationPacket::decode(packet)?.into_owned())
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

    pub fn stats(&self) -> ReceiverStats {
        self.flows
            .get(&self.primary_flow_id)
            .expect("primary Main receiver flow must exist")
            .stats()
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
        let mut flow_ids = self.flows.keys().copied().collect::<Vec<_>>();
        flow_ids.sort_unstable();
        flow_ids
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
        if !self.flows.contains_key(&flow_id) && self.flows.len() >= self.max_flows {
            return Err(crate::Error::MainFlowCapacityExceeded {
                maximum: self.max_flows,
            });
        }
        let cname = self.cname.clone();
        let nack_mode = self.nack_mode;
        let recovery = self.recovery.clone();
        let congestion_control = self.congestion_control;
        Ok(self.flows.entry(flow_id).or_insert_with(|| {
            SimpleReceiverCore::new(flow_id, cname, nack_mode)
                .with_recovery_config(recovery, congestion_control)
        }))
    }

    fn decode_reduced<'a>(&mut self, packet: &'a [u8]) -> Result<DecodedReduced<'a>> {
        let (gre, _) = GreHeader::decode(packet)?;
        if gre.key.is_some() {
            let Some(key) = &mut self.rx_key else {
                return Err(crate::Error::UnsupportedGreProtocol(gre.protocol_type));
            };
            return Ok(DecodedReduced::Owned(decode_encrypted_reduced_packet(
                packet, key,
            )?));
        }
        Ok(DecodedReduced::Borrowed(ReducedPacket::decode(packet)?))
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

    fn ts_packet(pid: u16, label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xff; TS_PACKET_SIZE];
        packet[0] = TS_SYNC_BYTE;
        packet[1..3].copy_from_slice(&pid.to_be_bytes());
        packet[3] = 0x10;
        packet[4..4 + label.len()].copy_from_slice(label);
        packet
    }
}
