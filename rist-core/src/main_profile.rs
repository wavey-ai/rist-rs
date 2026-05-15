use crate::crypto::PskKey;
use crate::packet::gre::{
    decode_encrypted_reduced_packet, encode_buffer_negotiation_payload,
    encode_encrypted_reduced_payload, encode_keepalive_payload, encode_reduced_payload,
    BufferNegotiation, BufferNegotiationPacket, GreHeader, GreKeepalive, KeepalivePacket,
    OwnedReducedPacket, ReducedHeader, ReducedPacket,
};
use crate::packet::rtcp::NackMode;
use crate::simple::{ReceivedPayload, SimpleReceiverCore, SimpleSenderCore};
use crate::stats::{ReceiverStats, SenderStats};
use crate::Result;
use std::time::Instant;

pub const DEFAULT_VIRT_SRC_PORT: u16 = 1971;
pub const DEFAULT_VIRT_DST_PORT: u16 = 1968;

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
            gre_version: 2,
            next_gre_sequence: 0,
            virt_src_port: DEFAULT_VIRT_SRC_PORT,
            virt_dst_port: DEFAULT_VIRT_DST_PORT,
            tx_key: None,
            rx_key: None,
        }
    }

    pub fn with_ports(mut self, virt_src_port: u16, virt_dst_port: u16) -> Self {
        self.virt_src_port = virt_src_port;
        self.virt_dst_port = virt_dst_port;
        self
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

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> MainOutboundPacket {
        let packet = self.simple.send_payload(payload, ntp_timestamp, now);
        self.wrap_rtp(packet.sequence, packet.retry, &packet.bytes)
    }

    pub fn handle_feedback(&mut self, packet: &[u8]) -> Result<Vec<MainOutboundPacket>> {
        let packet = self.decode_reduced(packet)?;
        let retries = self.simple.handle_feedback(packet.payload())?;
        Ok(retries
            .into_iter()
            .map(|retry| self.wrap_rtp(retry.sequence, true, &retry.bytes))
            .collect())
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        MainControlPacket {
            gre_sequence,
            bytes: encode_keepalive_payload(self.gre_version, gre_sequence, keepalive),
        }
    }

    pub fn build_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        MainControlPacket {
            gre_sequence,
            bytes: encode_buffer_negotiation_payload(gre_sequence, negotiation),
        }
    }

    pub fn accept_keepalive<'a>(&self, packet: &'a [u8]) -> Result<KeepalivePacket<'a>> {
        KeepalivePacket::decode(packet)
    }

    pub fn accept_buffer_negotiation<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<BufferNegotiationPacket<'a>> {
        BufferNegotiationPacket::decode(packet)
    }

    pub fn stats(&self) -> SenderStats {
        self.simple.stats()
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

#[derive(Debug, Clone)]
pub struct MainReceiverCore {
    simple: SimpleReceiverCore,
    gre_version: u8,
    next_gre_sequence: u32,
    last_reduced: Option<ReducedHeader>,
    tx_key: Option<PskKey>,
    rx_key: Option<PskKey>,
}

impl MainReceiverCore {
    pub fn new(flow_id: u32, cname: impl Into<String>, nack_mode: NackMode) -> Self {
        Self {
            simple: SimpleReceiverCore::new(flow_id, cname, nack_mode),
            gre_version: 2,
            next_gre_sequence: 0,
            last_reduced: None,
            tx_key: None,
            rx_key: None,
        }
    }

    pub fn with_gre_version(mut self, gre_version: u8) -> Self {
        self.gre_version = gre_version;
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

    pub fn accept_packet(&mut self, packet: &[u8]) -> Result<ReceivedPayload> {
        let packet = self.decode_reduced(packet)?;
        self.last_reduced = Some(packet.reduced());
        self.simple.accept_packet(packet.payload())
    }

    pub fn build_feedback(&mut self) -> MainReceiverFeedback {
        let gre_sequence = self.next_gre_sequence();
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
        let feedback = self.simple.build_feedback_and_record();
        let bytes = if let Some(key) = &mut self.tx_key {
            encode_encrypted_reduced_payload(
                self.gre_version,
                gre_sequence,
                reduced,
                &feedback,
                key,
            )
        } else {
            encode_reduced_payload(self.gre_version, gre_sequence, reduced, &feedback)
        };
        MainReceiverFeedback {
            gre_sequence,
            bytes,
        }
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        MainControlPacket {
            gre_sequence,
            bytes: encode_keepalive_payload(self.gre_version, gre_sequence, keepalive),
        }
    }

    pub fn build_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> MainControlPacket {
        let gre_sequence = self.next_gre_sequence();
        MainControlPacket {
            gre_sequence,
            bytes: encode_buffer_negotiation_payload(gre_sequence, negotiation),
        }
    }

    pub fn accept_keepalive<'a>(&self, packet: &'a [u8]) -> Result<KeepalivePacket<'a>> {
        KeepalivePacket::decode(packet)
    }

    pub fn accept_buffer_negotiation<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<BufferNegotiationPacket<'a>> {
        BufferNegotiationPacket::decode(packet)
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.simple.missing_sequences()
    }

    pub fn stats(&self) -> ReceiverStats {
        self.simple.stats()
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
    use crate::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use crate::packet::gre::{
        BufferNegotiationPacket, KeepalivePacket, GRE_PROTOCOL_TYPE_VSF,
        KEEPALIVE_CAP1_NULL_PACKET_DELETION, KEEPALIVE_CAP2_REDUCED_OVERHEAD,
    };
    use crate::packet::rtp::RtpPacket;
    use crate::time::ntp_from_unix_duration;
    use std::time::Duration;

    #[test]
    fn main_profile_wraps_rtp_in_reduced_gre() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let packet = sender.send_payload(b"payload", ntp, now);
        let decoded = ReducedPacket::decode(&packet.bytes).unwrap();
        assert_eq!(decoded.gre.sequence, Some(0));
        assert_eq!(decoded.reduced.src_port, DEFAULT_VIRT_SRC_PORT);
        assert_eq!(decoded.reduced.dst_port, DEFAULT_VIRT_DST_PORT);
        assert_eq!(decoded.payload[0], 0x80);
        assert_eq!(decoded.payload[1], 0x21);
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
        assert_eq!(decoded_keepalive.gre.protocol_type, GRE_PROTOCOL_TYPE_VSF);
        assert_eq!(decoded_keepalive.gre.sequence, Some(1));
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
    fn receiver_accepts_main_control_packets() {
        let mut sender = MainSenderCore::new(0x1122_3344, 64);
        let receiver = MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range);
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
    fn main_profile_encrypts_and_decrypts_payload() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let tx_key = PskKey::new(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let rx_key = PskKey::new(256, 0, b"secret", [0, 0, 0, 0]).unwrap();
        let mut sender = MainSenderCore::new(0x1122_3344, 64).with_tx_key(tx_key);
        let mut receiver =
            MainReceiverCore::new(0x1122_3344, "rust", NackMode::Range).with_rx_key(rx_key);

        let packet = sender.send_payload(b"payload", ntp, now);
        assert_eq!(&packet.bytes[..4], &[0x30, 0x50, 0xcc, 0xe0]);
        assert!(ReducedPacket::decode(&packet.bytes).is_err());

        let received = receiver.accept_packet(&packet.bytes).unwrap();
        assert_eq!(received.payload, b"payload");
    }

    #[test]
    fn main_profile_recovers_over_encrypted_feedback() {
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let sender_tx = PskKey::new(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let sender_rx = PskKey::new(256, 0, b"secret", [0, 0, 0, 0]).unwrap();
        let receiver_tx = PskKey::new(256, 0, b"secret", [5, 6, 7, 8]).unwrap();
        let receiver_rx = PskKey::new(256, 0, b"secret", [0, 0, 0, 0]).unwrap();
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
        assert_eq!(&feedback.bytes[..4], &[0x30, 0x50, 0xcc, 0xe0]);
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
