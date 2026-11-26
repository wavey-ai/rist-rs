use crate::auth::EapolFrame;
use crate::crypto::{AesKeySize, DecryptVerdict, PskKey};
use crate::{Error, Result};

pub const GRE_PROTOCOL_TYPE_KEEPALIVE: u16 = 0x88b5;
pub const GRE_PROTOCOL_TYPE_REDUCED: u16 = 0x88b6;
pub const GRE_PROTOCOL_TYPE_FULL: u16 = 0x0800;
pub const GRE_PROTOCOL_TYPE_EAPOL: u16 = 0x888e;
pub const GRE_PROTOCOL_TYPE_VSF: u16 = 0xcce0;
pub const VSF_PROTOCOL_TYPE_RIST: u16 = 0x0000;
pub const VSF_SUBTYPE_REDUCED: u16 = 0x0000;
pub const VSF_SUBTYPE_KEEPALIVE: u16 = 0x8000;
pub const VSF_SUBTYPE_FUTURE_NONCE: u16 = 0x8001;
pub const VSF_SUBTYPE_BUFFER_NEGOTIATION: u16 = 0x8002;
pub const GRE_FLAG_SEQUENCE: u8 = 1 << 4;
pub const GRE_FLAG_KEY: u8 = 1 << 5;
pub const GRE_FLAG_ROUTING: u8 = 1 << 6;
pub const GRE_FLAG_CHECKSUM: u8 = 1 << 7;
pub const KEEPALIVE_CAP1_NULL_PACKET_DELETION: u8 = 1 << 0;
pub const KEEPALIVE_CAP1_SMPTE_2022_7: u8 = 1 << 2;
pub const KEEPALIVE_CAP1_BONDING: u8 = 1 << 5;
pub const KEEPALIVE_CAP2_REDUCED_OVERHEAD: u8 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreHeader {
    pub protocol_type: u16,
    pub version: u8,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
}

impl GreHeader {
    pub const MIN_LEN: usize = 4;

    pub fn encode(self, out: &mut Vec<u8>) {
        self.encode_with_flags2_extra(out, 0);
    }

    pub fn encode_with_flags2_extra(self, out: &mut Vec<u8>, flags2_extra: u8) {
        let mut flags1 = 0u8;
        if self.key.is_some() {
            flags1 |= GRE_FLAG_KEY;
        }
        if self.sequence.is_some() {
            flags1 |= GRE_FLAG_SEQUENCE;
        }
        out.push(flags1);
        out.push(((self.version & 0x07) << 3) | flags2_extra);
        out.extend_from_slice(&self.protocol_type.to_be_bytes());
        if let Some(key) = self.key {
            out.extend_from_slice(&key.to_be_bytes());
        }
        if let Some(sequence) = self.sequence {
            out.extend_from_slice(&sequence.to_be_bytes());
        }
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < Self::MIN_LEN {
            return Err(Error::PacketTooShort {
                needed: Self::MIN_LEN,
                actual: input.len(),
            });
        }

        let flags1 = input[0];
        // As librist: a routing bit or reserved flags make the packet
        // non-conformant for RIST Main.
        if flags1 & GRE_FLAG_ROUTING != 0 || input[1] & 0x07 != 0 {
            return Err(Error::NonConformantGre);
        }
        let version = (input[1] >> 3) & 0x07;
        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        let mut offset = Self::MIN_LEN;
        if flags1 & GRE_FLAG_CHECKSUM != 0 {
            // Checksum and reserved word: skipped (not verified), as librist does.
            if input.len() < offset + 4 {
                return Err(Error::PacketTooShort {
                    needed: offset + 4,
                    actual: input.len(),
                });
            }
            offset += 4;
        }
        let key = if flags1 & GRE_FLAG_KEY != 0 {
            if input.len() < offset + 4 {
                return Err(Error::PacketTooShort {
                    needed: offset + 4,
                    actual: input.len(),
                });
            }
            let value = u32::from_be_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
            ]);
            offset += 4;
            Some(value)
        } else {
            None
        };

        let sequence = if flags1 & GRE_FLAG_SEQUENCE != 0 {
            if input.len() < offset + 4 {
                return Err(Error::PacketTooShort {
                    needed: offset + 4,
                    actual: input.len(),
                });
            }
            let value = u32::from_be_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
            ]);
            offset += 4;
            Some(value)
        } else {
            None
        };

        Ok((
            Self {
                protocol_type,
                version,
                key,
                sequence,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsfHeader {
    pub protocol_type: u16,
    pub subtype: u16,
}

impl VsfHeader {
    pub const LEN: usize = 4;

    pub fn rist_reduced() -> Self {
        Self {
            protocol_type: VSF_PROTOCOL_TYPE_RIST,
            subtype: VSF_SUBTYPE_REDUCED,
        }
    }

    pub fn rist_keepalive() -> Self {
        Self {
            protocol_type: VSF_PROTOCOL_TYPE_RIST,
            subtype: VSF_SUBTYPE_KEEPALIVE,
        }
    }

    pub fn rist_buffer_negotiation() -> Self {
        Self {
            protocol_type: VSF_PROTOCOL_TYPE_RIST,
            subtype: VSF_SUBTYPE_BUFFER_NEGOTIATION,
        }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.protocol_type.to_be_bytes());
        out.extend_from_slice(&self.subtype.to_be_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::LEN {
            return Err(Error::PacketTooShort {
                needed: Self::LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            protocol_type: u16::from_be_bytes([input[0], input[1]]),
            subtype: u16::from_be_bytes([input[2], input[3]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreKeepalive<'a> {
    pub mac: [u8; 6],
    pub capabilities1: u8,
    pub capabilities2: u8,
    pub json: &'a [u8],
}

impl<'a> GreKeepalive<'a> {
    pub const MIN_LEN: usize = 8;

    pub fn librist_default(mac: [u8; 6]) -> Self {
        Self {
            mac,
            capabilities1: KEEPALIVE_CAP1_NULL_PACKET_DELETION
                | KEEPALIVE_CAP1_SMPTE_2022_7
                | KEEPALIVE_CAP1_BONDING,
            capabilities2: KEEPALIVE_CAP2_REDUCED_OVERHEAD,
            json: &[],
        }
    }

    pub fn supports_null_packet_deletion(self) -> bool {
        self.capabilities1 & KEEPALIVE_CAP1_NULL_PACKET_DELETION != 0
    }

    pub fn supports_reduced_overhead(self) -> bool {
        self.capabilities2 & KEEPALIVE_CAP2_REDUCED_OVERHEAD != 0
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mac);
        out.push(self.capabilities1);
        out.push(self.capabilities2);
        out.extend_from_slice(self.json);
    }

    pub fn decode(input: &'a [u8]) -> Result<Self> {
        if input.len() < Self::MIN_LEN {
            return Err(Error::PacketTooShort {
                needed: Self::MIN_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            mac: [input[0], input[1], input[2], input[3], input[4], input[5]],
            capabilities1: input[6],
            capabilities2: input[7],
            json: &input[8..],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepalivePacket<'a> {
    pub gre: GreHeader,
    pub vsf: Option<VsfHeader>,
    pub keepalive: GreKeepalive<'a>,
}

impl<'a> KeepalivePacket<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        let (gre, offset) = GreHeader::decode(input)?;
        if gre.key.is_some() {
            return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
        }
        Self::decode_after_gre(gre, &input[offset..])
    }

    fn decode_after_gre(gre: GreHeader, input: &'a [u8]) -> Result<Self> {
        let mut offset = 0;
        let vsf = match gre.protocol_type {
            GRE_PROTOCOL_TYPE_KEEPALIVE => None,
            GRE_PROTOCOL_TYPE_VSF => {
                let vsf = VsfHeader::decode(&input[offset..])?;
                if vsf.protocol_type != VSF_PROTOCOL_TYPE_RIST {
                    return Err(Error::UnsupportedGreProtocol(vsf.protocol_type));
                }
                if vsf.subtype != VSF_SUBTYPE_KEEPALIVE {
                    return Err(Error::UnsupportedVsfSubtype(vsf.subtype));
                }
                offset += VsfHeader::LEN;
                Some(vsf)
            }
            other => return Err(Error::UnsupportedGreProtocol(other)),
        };
        Ok(Self {
            gre,
            vsf,
            keepalive: GreKeepalive::decode(&input[offset..])?,
        })
    }

    pub fn into_owned(self) -> OwnedKeepalivePacket {
        OwnedKeepalivePacket {
            gre: self.gre,
            vsf: self.vsf,
            keepalive: self.keepalive.into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedGreKeepalive {
    pub mac: [u8; 6],
    pub capabilities1: u8,
    pub capabilities2: u8,
    pub json: Vec<u8>,
}

impl GreKeepalive<'_> {
    pub fn into_owned(self) -> OwnedGreKeepalive {
        OwnedGreKeepalive {
            mac: self.mac,
            capabilities1: self.capabilities1,
            capabilities2: self.capabilities2,
            json: self.json.to_vec(),
        }
    }
}

impl OwnedGreKeepalive {
    pub fn supports_null_packet_deletion(&self) -> bool {
        self.capabilities1 & KEEPALIVE_CAP1_NULL_PACKET_DELETION != 0
    }

    pub fn supports_reduced_overhead(&self) -> bool {
        self.capabilities2 & KEEPALIVE_CAP2_REDUCED_OVERHEAD != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedKeepalivePacket {
    pub gre: GreHeader,
    pub vsf: Option<VsfHeader>,
    pub keepalive: OwnedGreKeepalive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferNegotiation<'a> {
    pub sender_max_buffer_ms: u16,
    pub receiver_current_buffer_ms: u16,
    pub protocol_type: u16,
    pub protocol_data: &'a [u8],
}

impl<'a> BufferNegotiation<'a> {
    pub const MIN_LEN: usize = 6;

    pub fn session(sender_max_buffer_ms: u16, receiver_current_buffer_ms: u16) -> Self {
        Self {
            sender_max_buffer_ms,
            receiver_current_buffer_ms,
            protocol_type: 0,
            protocol_data: &[],
        }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sender_max_buffer_ms.to_be_bytes());
        out.extend_from_slice(&self.receiver_current_buffer_ms.to_be_bytes());
        out.extend_from_slice(&self.protocol_type.to_be_bytes());
        out.extend_from_slice(self.protocol_data);
    }

    pub fn decode(input: &'a [u8]) -> Result<Self> {
        if input.len() < Self::MIN_LEN {
            return Err(Error::PacketTooShort {
                needed: Self::MIN_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            sender_max_buffer_ms: u16::from_be_bytes([input[0], input[1]]),
            receiver_current_buffer_ms: u16::from_be_bytes([input[2], input[3]]),
            protocol_type: u16::from_be_bytes([input[4], input[5]]),
            protocol_data: &input[6..],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferNegotiationPacket<'a> {
    pub gre: GreHeader,
    pub vsf: VsfHeader,
    pub negotiation: BufferNegotiation<'a>,
}

impl<'a> BufferNegotiationPacket<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        let (gre, offset) = GreHeader::decode(input)?;
        if gre.key.is_some() {
            return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
        }
        Self::decode_after_gre(gre, &input[offset..])
    }

    fn decode_after_gre(gre: GreHeader, input: &'a [u8]) -> Result<Self> {
        let mut offset = 0;
        if gre.protocol_type != GRE_PROTOCOL_TYPE_VSF {
            return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
        }
        let vsf = VsfHeader::decode(&input[offset..])?;
        if vsf.protocol_type != VSF_PROTOCOL_TYPE_RIST {
            return Err(Error::UnsupportedGreProtocol(vsf.protocol_type));
        }
        if vsf.subtype != VSF_SUBTYPE_BUFFER_NEGOTIATION {
            return Err(Error::UnsupportedVsfSubtype(vsf.subtype));
        }
        offset += VsfHeader::LEN;
        Ok(Self {
            gre,
            vsf,
            negotiation: BufferNegotiation::decode(&input[offset..])?,
        })
    }

    pub fn into_owned(self) -> OwnedBufferNegotiationPacket {
        OwnedBufferNegotiationPacket {
            gre: self.gre,
            vsf: self.vsf,
            negotiation: self.negotiation.into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBufferNegotiation {
    pub sender_max_buffer_ms: u16,
    pub receiver_current_buffer_ms: u16,
    pub protocol_type: u16,
    pub protocol_data: Vec<u8>,
}

impl BufferNegotiation<'_> {
    pub fn into_owned(self) -> OwnedBufferNegotiation {
        OwnedBufferNegotiation {
            sender_max_buffer_ms: self.sender_max_buffer_ms,
            receiver_current_buffer_ms: self.receiver_current_buffer_ms,
            protocol_type: self.protocol_type,
            protocol_data: self.protocol_data.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBufferNegotiationPacket {
    pub gre: GreHeader,
    pub vsf: VsfHeader,
    pub negotiation: OwnedBufferNegotiation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolGrePacket {
    pub gre: GreHeader,
    pub frame: EapolFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedOobPacket {
    pub gre: GreHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainPacket {
    Reduced(OwnedReducedPacket),
    Keepalive(OwnedKeepalivePacket),
    BufferNegotiation(OwnedBufferNegotiationPacket),
    Eapol(EapolGrePacket),
    Oob(OwnedOobPacket),
    FutureNonce {
        gre: GreHeader,
        payload: Vec<u8>,
    },
    Unknown {
        gre: GreHeader,
        vsf: Option<VsfHeader>,
        payload: Vec<u8>,
    },
}

/// Parses one Main-profile datagram exactly once at the GRE boundary and
/// decrypts its payload at most once before typed dispatch.
///
/// With a key, everything but EAPOL must arrive encrypted (GRE key and
/// sequence present): a clear packet is dropped and counted, as librist
/// ignores clear packets when it has a key. An encrypted packet must pass
/// the checks of [`check_decrypted`] after decryption.
pub fn decode_main_packet(input: &[u8], key: Option<&mut PskKey>) -> Result<MainPacket> {
    let (gre, offset) = GreHeader::decode(input)?;
    if gre.protocol_type == GRE_PROTOCOL_TYPE_EAPOL && (gre.key.is_none() || key.is_some()) {
        // EAPOL is never encrypted; librist reads it past any key field.
        return Ok(MainPacket::Eapol(EapolGrePacket {
            gre,
            frame: EapolFrame::decode(&input[offset..])?,
        }));
    }
    let payload = if let Some(key) = key {
        require_encrypted(&gre, key)?;
        decrypt_checked(gre, &input[offset..], key)?
    } else if gre.key.is_some() {
        return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
    } else {
        let payload = &input[offset..];
        if is_reduced_payload(gre, payload) {
            // Data path: copy only the media payload, not the whole datagram.
            let packet = ReducedPacket::decode_after_gre(gre, payload)?;
            return Ok(MainPacket::Reduced(OwnedReducedPacket {
                gre,
                vsf: packet.vsf,
                reduced: packet.reduced,
                payload: packet.payload.to_vec(),
            }));
        }
        payload.to_vec()
    };

    decode_main_payload(gre, payload)
}

/// With a key configured, only EAPOL may arrive unencrypted; any other
/// packet without both the GRE key (nonce) and sequence is dropped and
/// counted in `clear_packets_dropped`.
pub fn require_encrypted(gre: &GreHeader, key: &mut PskKey) -> Result<()> {
    if gre.protocol_type == GRE_PROTOCOL_TYPE_EAPOL || (gre.key.is_some() && gre.sequence.is_some())
    {
        return Ok(());
    }
    key.note_clear_dropped();
    Err(Error::ClearPacketWithPsk)
}

/// Whether [`require_encrypted`] would drop `input`: a GRE packet that
/// arrived clear, other than EAPOL. Counts it on `key` when it would.
pub fn screen_clear_datagram(input: &[u8], key: &mut PskKey) -> Result<()> {
    let (gre, _) = GreHeader::decode(input)?;
    require_encrypted(&gre, key)
}

/// Decrypts the payload of an encrypted packet and applies the RIST Main
/// PSK checks: a known GRE protocol type, a nonce that is not shut out, a
/// nonce change the rate limit allows, and decrypted contents that pass
/// [`check_decrypted`]. Each rejection is counted on `key`.
fn decrypt_checked(gre: GreHeader, body: &[u8], key: &mut PskKey) -> Result<Vec<u8>> {
    let (Some(nonce), Some(sequence)) = (gre.key, gre.sequence) else {
        return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
    };
    let nonce = nonce.to_be_bytes();
    if !matches!(
        gre.protocol_type,
        GRE_PROTOCOL_TYPE_REDUCED
            | GRE_PROTOCOL_TYPE_KEEPALIVE
            | GRE_PROTOCOL_TYPE_VSF
            | GRE_PROTOCOL_TYPE_FULL
    ) {
        key.note_rejected();
        return Err(Error::PskCheckFailed);
    }
    key.refuse_latched(nonce)?;
    let decrypted = match key.decrypt(nonce, gre.version, sequence, body) {
        Ok(decrypted) => decrypted,
        Err(error) => {
            key.note_rejected();
            return Err(error);
        }
    };
    let verdict = check_decrypted(gre.protocol_type, &decrypted);
    key.record_verdict(nonce, verdict);
    if verdict == DecryptVerdict::Bad {
        return Err(Error::PskCheckFailed);
    }
    Ok(decrypted)
}

/// The checks RIST Main PSK allows on a decrypted payload. AES-CTR has no
/// authentication tag, so a wrong passphrase (or a forged or damaged
/// packet) shows only as contents that are not a valid RIST packet:
///
/// - VSF: protocol 0 (RIST) and a subtype in use (reduced, keepalive,
///   buffer negotiation), as librist requires.
/// - Reduced (data and RTCP): the reduced header and a full RTP header
///   with version 2 (librist's check). Data must be MPEG-TS over RTP as
///   librist and rist-rs send it: no padding, no CSRC, payload type 33,
///   and when the extension bit is set the RIST extension ("RI", one
///   word). RTCP must be a well-formed compound: every packet version 2
///   with an RTCP payload type, lengths that end exactly at the end.
/// - Keepalive: MAC and capabilities, then nothing, the four-byte TR-06-3
///   capabilities, or a JSON object.
/// - Buffer negotiation: its six fixed bytes.
/// - Out-of-band (GRE full) data is opaque and cannot be checked.
///
/// Only RTP and RTCP give a [`DecryptVerdict::Strong`] result: a wrong key
/// passes them by chance (about one data packet in 2^15), the rest carry
/// too little structure to tell.
pub fn check_decrypted(protocol_type: u16, payload: &[u8]) -> DecryptVerdict {
    match protocol_type {
        GRE_PROTOCOL_TYPE_REDUCED => check_reduced_body(payload),
        GRE_PROTOCOL_TYPE_KEEPALIVE => check_keepalive_body(payload),
        GRE_PROTOCOL_TYPE_FULL => DecryptVerdict::Weak,
        GRE_PROTOCOL_TYPE_VSF => {
            let Ok(vsf) = VsfHeader::decode(payload) else {
                return DecryptVerdict::Bad;
            };
            if vsf.protocol_type != VSF_PROTOCOL_TYPE_RIST {
                return DecryptVerdict::Bad;
            }
            let body = &payload[VsfHeader::LEN..];
            match vsf.subtype {
                VSF_SUBTYPE_REDUCED => check_reduced_body(body),
                VSF_SUBTYPE_KEEPALIVE => check_keepalive_body(body),
                VSF_SUBTYPE_BUFFER_NEGOTIATION if body.len() >= BufferNegotiation::MIN_LEN => {
                    DecryptVerdict::Weak
                }
                _ => DecryptVerdict::Bad,
            }
        }
        _ => DecryptVerdict::Bad,
    }
}

const RTP_FIXED_HEADER_LEN: usize = 12;

fn check_reduced_body(body: &[u8]) -> DecryptVerdict {
    if body.len() < ReducedHeader::LEN + RTP_FIXED_HEADER_LEN {
        return DecryptVerdict::Bad;
    }
    let rtp = &body[ReducedHeader::LEN..];
    // librist and rist-rs tell RTCP from RTP by payload type 72-77
    // (200-205 with the marker bit).
    let checked = if (72..=77).contains(&(rtp[1] & 0x7f)) {
        rtcp_compound_is_well_formed(rtp)
    } else {
        rtp_data_header_is_valid(rtp)
    };
    if checked {
        DecryptVerdict::Strong
    } else {
        DecryptVerdict::Bad
    }
}

fn rtp_data_header_is_valid(rtp: &[u8]) -> bool {
    // Version 2, no padding, no CSRC (the extension bit is checked below).
    if rtp[0] & 0xef != 0x80 {
        return false;
    }
    if rtp[1] & 0x7f != crate::packet::rtp::RTP_PAYLOAD_TYPE_MPEGTS {
        return false;
    }
    if rtp[0] & 0x10 != 0 {
        let extension_end = RTP_FIXED_HEADER_LEN + crate::packet::rtp::RIST_RTP_EXTENSION_LEN;
        if rtp.len() < extension_end
            || rtp[12..14] != crate::packet::rtp::RIST_RTP_EXTENSION_IDENTIFIER
            || u16::from_be_bytes([rtp[14], rtp[15]])
                != crate::packet::rtp::RIST_RTP_EXTENSION_WORDS
        {
            return false;
        }
    }
    true
}

fn rtcp_compound_is_well_formed(mut rtcp: &[u8]) -> bool {
    while !rtcp.is_empty() {
        if rtcp.len() < 4 || rtcp[0] >> 6 != 2 {
            return false;
        }
        let payload_type = rtcp[1];
        if !(192..=223).contains(&payload_type) && !(72..=79).contains(&(payload_type & 0x7f)) {
            return false;
        }
        let len = (usize::from(u16::from_be_bytes([rtcp[2], rtcp[3]])) + 1) * 4;
        if len > rtcp.len() {
            return false;
        }
        rtcp = &rtcp[len..];
    }
    true
}

fn check_keepalive_body(body: &[u8]) -> DecryptVerdict {
    if body.len() < GreKeepalive::MIN_LEN {
        return DecryptVerdict::Bad;
    }
    let rest = &body[GreKeepalive::MIN_LEN..];
    let end = rest
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |at| at + 1);
    let json = &rest[..end];
    let valid = rest.is_empty()
        || rest.len() == 4
        || (json.first() == Some(&b'{')
            && json.last() == Some(&b'}')
            && std::str::from_utf8(json).is_ok());
    if valid {
        DecryptVerdict::Weak
    } else {
        DecryptVerdict::Bad
    }
}

fn is_reduced_payload(gre: GreHeader, payload: &[u8]) -> bool {
    match gre.protocol_type {
        GRE_PROTOCOL_TYPE_REDUCED => true,
        GRE_PROTOCOL_TYPE_VSF => VsfHeader::decode(payload).is_ok_and(|vsf| {
            vsf.protocol_type == VSF_PROTOCOL_TYPE_RIST && vsf.subtype == VSF_SUBTYPE_REDUCED
        }),
        _ => false,
    }
}

/// Builds an owned reduced packet from a decrypted buffer by dropping the
/// headers in place instead of copying the payload into a new allocation.
fn owned_reduced_from_buffer(gre: GreHeader, mut payload: Vec<u8>) -> Result<MainPacket> {
    let (vsf, reduced, header_len) = {
        let packet = ReducedPacket::decode_after_gre(gre, &payload)?;
        (
            packet.vsf,
            packet.reduced,
            payload.len() - packet.payload.len(),
        )
    };
    payload.drain(..header_len);
    Ok(MainPacket::Reduced(OwnedReducedPacket {
        gre,
        vsf,
        reduced,
        payload,
    }))
}

fn decode_main_payload(gre: GreHeader, payload: Vec<u8>) -> Result<MainPacket> {
    match gre.protocol_type {
        GRE_PROTOCOL_TYPE_REDUCED => owned_reduced_from_buffer(gre, payload),
        GRE_PROTOCOL_TYPE_KEEPALIVE => Ok(MainPacket::Keepalive(
            KeepalivePacket::decode_after_gre(gre, &payload)?.into_owned(),
        )),
        GRE_PROTOCOL_TYPE_EAPOL if gre.key.is_none() => Ok(MainPacket::Eapol(EapolGrePacket {
            gre,
            frame: EapolFrame::decode(&payload)?,
        })),
        GRE_PROTOCOL_TYPE_FULL => Ok(MainPacket::Oob(OwnedOobPacket { gre, payload })),
        GRE_PROTOCOL_TYPE_VSF => {
            let vsf = VsfHeader::decode(&payload)?;
            if vsf.protocol_type != VSF_PROTOCOL_TYPE_RIST {
                return Ok(MainPacket::Unknown {
                    gre,
                    vsf: Some(vsf),
                    payload,
                });
            }
            match vsf.subtype {
                VSF_SUBTYPE_REDUCED => owned_reduced_from_buffer(gre, payload),
                VSF_SUBTYPE_KEEPALIVE => Ok(MainPacket::Keepalive(
                    KeepalivePacket::decode_after_gre(gre, &payload)?.into_owned(),
                )),
                VSF_SUBTYPE_BUFFER_NEGOTIATION => Ok(MainPacket::BufferNegotiation(
                    BufferNegotiationPacket::decode_after_gre(gre, &payload)?.into_owned(),
                )),
                VSF_SUBTYPE_FUTURE_NONCE => Ok(MainPacket::FutureNonce { gre, payload }),
                _ => Ok(MainPacket::Unknown {
                    gre,
                    vsf: Some(vsf),
                    payload,
                }),
            }
        }
        _ => Ok(MainPacket::Unknown {
            gre,
            vsf: None,
            payload,
        }),
    }
}

impl EapolGrePacket {
    pub fn decode(input: &[u8]) -> Result<Self> {
        decode_eapol_payload(input)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

impl ReducedHeader {
    pub const LEN: usize = 4;

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::LEN {
            return Err(Error::PacketTooShort {
                needed: Self::LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            src_port: u16::from_be_bytes([input[0], input[1]]),
            dst_port: u16::from_be_bytes([input[2], input[3]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedPacket<'a> {
    pub gre: GreHeader,
    pub vsf: Option<VsfHeader>,
    pub reduced: ReducedHeader,
    pub payload: &'a [u8],
}

impl<'a> ReducedPacket<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        let (gre, offset) = GreHeader::decode(input)?;
        if gre.key.is_some() {
            return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
        }
        Self::decode_after_gre(gre, &input[offset..])
    }

    fn decode_after_gre(gre: GreHeader, input: &'a [u8]) -> Result<Self> {
        let mut offset = 0;
        let vsf = match gre.protocol_type {
            GRE_PROTOCOL_TYPE_REDUCED => None,
            GRE_PROTOCOL_TYPE_VSF => {
                let vsf = VsfHeader::decode(&input[offset..])?;
                if vsf.protocol_type != VSF_PROTOCOL_TYPE_RIST {
                    return Err(Error::UnsupportedGreProtocol(vsf.protocol_type));
                }
                if vsf.subtype != VSF_SUBTYPE_REDUCED {
                    return Err(Error::UnsupportedVsfSubtype(vsf.subtype));
                }
                offset += VsfHeader::LEN;
                Some(vsf)
            }
            other => return Err(Error::UnsupportedGreProtocol(other)),
        };
        let reduced = ReducedHeader::decode(&input[offset..])?;
        offset += ReducedHeader::LEN;
        Ok(Self {
            gre,
            vsf,
            reduced,
            payload: &input[offset..],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedReducedPacket {
    pub gre: GreHeader,
    pub vsf: Option<VsfHeader>,
    pub reduced: ReducedHeader,
    pub payload: Vec<u8>,
}

/// The largest header [`reduced_header`] writes: GRE with sequence (8),
/// VSF (4) and the reduced ports (4).
pub const MAX_REDUCED_HEADER_LEN: usize = 16;

/// The unencrypted header [`encode_reduced_payload`] puts before its
/// payload, built on the stack, so a sender can send the header and a
/// stored RTP packet as two parts of one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedHeaderBytes {
    bytes: [u8; MAX_REDUCED_HEADER_LEN],
    len: u8,
}

impl ReducedHeaderBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

pub fn reduced_header(
    gre_version: u8,
    sequence: u32,
    reduced: ReducedHeader,
) -> ReducedHeaderBytes {
    let use_vsf = gre_version >= 2;
    let mut bytes = [0u8; MAX_REDUCED_HEADER_LEN];
    bytes[0] = GRE_FLAG_SEQUENCE;
    bytes[1] = (gre_version & 0x07) << 3;
    let protocol_type = if use_vsf {
        GRE_PROTOCOL_TYPE_VSF
    } else {
        GRE_PROTOCOL_TYPE_REDUCED
    };
    bytes[2..4].copy_from_slice(&protocol_type.to_be_bytes());
    bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
    let mut len = 8;
    if use_vsf {
        let vsf = VsfHeader::rist_reduced();
        bytes[8..10].copy_from_slice(&vsf.protocol_type.to_be_bytes());
        bytes[10..12].copy_from_slice(&vsf.subtype.to_be_bytes());
        len = 12;
    }
    bytes[len..len + 2].copy_from_slice(&reduced.src_port.to_be_bytes());
    bytes[len + 2..len + 4].copy_from_slice(&reduced.dst_port.to_be_bytes());
    ReducedHeaderBytes {
        bytes,
        len: (len + 4) as u8,
    }
}

pub fn encode_reduced_payload(
    gre_version: u8,
    sequence: u32,
    reduced: ReducedHeader,
    payload: &[u8],
) -> Vec<u8> {
    let use_vsf = gre_version >= 2;
    let mut out = Vec::with_capacity(12 + payload.len());
    GreHeader {
        protocol_type: if use_vsf {
            GRE_PROTOCOL_TYPE_VSF
        } else {
            GRE_PROTOCOL_TYPE_REDUCED
        },
        version: gre_version,
        key: None,
        sequence: Some(sequence),
    }
    .encode(&mut out);
    if use_vsf {
        VsfHeader::rist_reduced().encode(&mut out);
    }
    reduced.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

pub fn encode_encrypted_reduced_payload(
    gre_version: u8,
    sequence: u32,
    reduced: ReducedHeader,
    payload: &[u8],
    key: &mut PskKey,
) -> Vec<u8> {
    let use_vsf = gre_version >= 2;
    let mut encrypted_payload = Vec::with_capacity(8 + payload.len());
    if use_vsf {
        VsfHeader::rist_reduced().encode(&mut encrypted_payload);
    }
    reduced.encode(&mut encrypted_payload);
    encrypted_payload.extend_from_slice(payload);
    let encrypted_payload = key.encrypt(gre_version, sequence, &encrypted_payload);

    let mut out = Vec::with_capacity(12 + encrypted_payload.len());
    GreHeader {
        protocol_type: if use_vsf {
            GRE_PROTOCOL_TYPE_VSF
        } else {
            GRE_PROTOCOL_TYPE_REDUCED
        },
        version: gre_version,
        key: Some(u32::from_be_bytes(key.nonce())),
        sequence: Some(sequence),
    }
    .encode_with_flags2_extra(
        &mut out,
        if gre_version >= 1 && key.key_size() == AesKeySize::Aes256 {
            1 << 6
        } else {
            0
        },
    );
    out.extend_from_slice(&encrypted_payload);
    out
}

pub fn encode_oob_payload(gre_version: u8, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GreHeader::MIN_LEN + 4 + payload.len());
    GreHeader {
        protocol_type: GRE_PROTOCOL_TYPE_FULL,
        version: gre_version,
        key: None,
        sequence: Some(sequence),
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    out
}

pub fn encode_encrypted_oob_payload(
    gre_version: u8,
    sequence: u32,
    payload: &[u8],
    key: &mut PskKey,
) -> Vec<u8> {
    encode_encrypted_gre_payload(gre_version, GRE_PROTOCOL_TYPE_FULL, sequence, payload, key)
}

pub fn decode_encrypted_reduced_packet(
    input: &[u8],
    key: &mut PskKey,
) -> Result<OwnedReducedPacket> {
    let (gre, offset) = GreHeader::decode(input)?;
    require_encrypted(&gre, key)?;
    let decrypted = decrypt_checked(gre, &input[offset..], key)?;
    let packet = ReducedPacket::decode_after_gre(gre, &decrypted)?;
    Ok(OwnedReducedPacket {
        gre: packet.gre,
        vsf: packet.vsf,
        reduced: packet.reduced,
        payload: packet.payload.to_vec(),
    })
}

fn encode_encrypted_gre_payload(
    gre_version: u8,
    protocol_type: u16,
    sequence: u32,
    payload: &[u8],
    key: &mut PskKey,
) -> Vec<u8> {
    let encrypted_payload = key.encrypt(gre_version, sequence, payload);
    let mut out = Vec::with_capacity(12 + encrypted_payload.len());
    GreHeader {
        protocol_type,
        version: gre_version,
        key: Some(u32::from_be_bytes(key.nonce())),
        sequence: Some(sequence),
    }
    .encode_with_flags2_extra(
        &mut out,
        if gre_version >= 1 && key.key_size() == AesKeySize::Aes256 {
            1 << 6
        } else {
            0
        },
    );
    out.extend_from_slice(&encrypted_payload);
    out
}

fn decrypt_gre_payload(input: &[u8], key: &mut PskKey) -> Result<(GreHeader, Vec<u8>)> {
    let (gre, offset) = GreHeader::decode(input)?;
    require_encrypted(&gre, key)?;
    let decrypted = decrypt_checked(gre, &input[offset..], key)?;
    Ok((gre, decrypted))
}

pub fn encode_keepalive_payload(
    gre_version: u8,
    sequence: u32,
    keepalive: GreKeepalive<'_>,
) -> Vec<u8> {
    let use_vsf = gre_version >= 2;
    let mut out = Vec::with_capacity(16 + GreKeepalive::MIN_LEN + keepalive.json.len());
    GreHeader {
        protocol_type: if use_vsf {
            GRE_PROTOCOL_TYPE_VSF
        } else {
            GRE_PROTOCOL_TYPE_KEEPALIVE
        },
        version: gre_version,
        key: None,
        sequence: Some(sequence),
    }
    .encode(&mut out);
    if use_vsf {
        VsfHeader::rist_keepalive().encode(&mut out);
    }
    keepalive.encode(&mut out);
    out
}

pub fn encode_encrypted_keepalive_payload(
    gre_version: u8,
    sequence: u32,
    keepalive: GreKeepalive<'_>,
    key: &mut PskKey,
) -> Vec<u8> {
    let use_vsf = gre_version >= 2;
    let mut payload =
        Vec::with_capacity(VsfHeader::LEN + GreKeepalive::MIN_LEN + keepalive.json.len());
    if use_vsf {
        VsfHeader::rist_keepalive().encode(&mut payload);
    }
    keepalive.encode(&mut payload);
    encode_encrypted_gre_payload(
        gre_version,
        if use_vsf {
            GRE_PROTOCOL_TYPE_VSF
        } else {
            GRE_PROTOCOL_TYPE_KEEPALIVE
        },
        sequence,
        &payload,
        key,
    )
}

pub fn decode_encrypted_keepalive_packet(
    input: &[u8],
    key: &mut PskKey,
) -> Result<OwnedKeepalivePacket> {
    let (gre, decrypted) = decrypt_gre_payload(input, key)?;
    Ok(KeepalivePacket::decode_after_gre(gre, &decrypted)?.into_owned())
}

pub fn encode_buffer_negotiation_payload(
    sequence: u32,
    negotiation: BufferNegotiation<'_>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + negotiation.protocol_data.len());
    GreHeader {
        protocol_type: GRE_PROTOCOL_TYPE_VSF,
        version: 2,
        key: None,
        sequence: Some(sequence),
    }
    .encode(&mut out);
    VsfHeader::rist_buffer_negotiation().encode(&mut out);
    negotiation.encode(&mut out);
    out
}

pub fn encode_encrypted_buffer_negotiation_payload(
    sequence: u32,
    negotiation: BufferNegotiation<'_>,
    key: &mut PskKey,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        VsfHeader::LEN + BufferNegotiation::MIN_LEN + negotiation.protocol_data.len(),
    );
    VsfHeader::rist_buffer_negotiation().encode(&mut payload);
    negotiation.encode(&mut payload);
    encode_encrypted_gre_payload(2, GRE_PROTOCOL_TYPE_VSF, sequence, &payload, key)
}

pub fn decode_encrypted_buffer_negotiation_packet(
    input: &[u8],
    key: &mut PskKey,
) -> Result<OwnedBufferNegotiationPacket> {
    let (gre, decrypted) = decrypt_gre_payload(input, key)?;
    Ok(BufferNegotiationPacket::decode_after_gre(gre, &decrypted)?.into_owned())
}

pub fn encode_eapol_payload(gre_version: u8, sequence: u32, frame: &EapolFrame) -> Result<Vec<u8>> {
    let payload = frame.encode()?;
    let mut out = Vec::with_capacity(8 + payload.len());
    GreHeader {
        protocol_type: GRE_PROTOCOL_TYPE_EAPOL,
        version: gre_version,
        key: None,
        sequence: Some(sequence),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_eapol_payload(input: &[u8]) -> Result<EapolGrePacket> {
    let (gre, offset) = GreHeader::decode(input)?;
    if gre.protocol_type != GRE_PROTOCOL_TYPE_EAPOL {
        return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
    }
    Ok(EapolGrePacket {
        gre,
        frame: EapolFrame::decode(&input[offset..])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{EapPacket, EAPOL_VERSION_3, EAP_TYPE_IDENTITY};
    use crate::packet::rtp::{encode_packet, RtpHeader};

    /// An MPEG-TS RTP packet as librist and rist-rs send it.
    fn rtp(sequence: u16, payload: &[u8]) -> Vec<u8> {
        encode_packet(
            RtpHeader::new_mpegts(sequence, 90_000, 0x1122_3344),
            payload,
        )
    }

    #[test]
    fn reduced_header_is_the_prefix_of_encode_reduced_payload() {
        let reduced = ReducedHeader {
            src_port: 0x1234,
            dst_port: 0xabcd,
        };
        for version in 0..=3 {
            let header = reduced_header(version, 0xdead_beef, reduced);
            let mut joined = header.as_slice().to_vec();
            joined.extend_from_slice(b"rtp bytes");
            assert_eq!(
                joined,
                encode_reduced_payload(version, 0xdead_beef, reduced, b"rtp bytes"),
                "GRE version {version}"
            );
            let decoded = ReducedPacket::decode(&joined).unwrap();
            assert_eq!(decoded.payload, b"rtp bytes");
            assert_eq!(decoded.gre.sequence, Some(0xdead_beef));
        }
    }

    #[test]
    fn gre_header_round_trips_sequence_shape() {
        let header = GreHeader {
            protocol_type: GRE_PROTOCOL_TYPE_REDUCED,
            version: 2,
            key: None,
            sequence: Some(0x0102_0304),
        };
        let mut out = Vec::new();
        header.encode(&mut out);
        assert_eq!(out, vec![0x10, 0x10, 0x88, 0xb6, 1, 2, 3, 4]);
        let (decoded, consumed) = GreHeader::decode(&out).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn reduced_header_round_trips() {
        let mut out = Vec::new();
        ReducedHeader {
            src_port: 1971,
            dst_port: 1968,
        }
        .encode(&mut out);
        assert_eq!(ReducedHeader::decode(&out).unwrap().dst_port, 1968);
    }

    #[test]
    fn reduced_packet_v1_round_trips() {
        let packet = encode_reduced_payload(
            1,
            42,
            ReducedHeader {
                src_port: 1971,
                dst_port: 1968,
            },
            b"payload",
        );
        assert_eq!(&packet[..8], &[0x10, 0x08, 0x88, 0xb6, 0, 0, 0, 42]);
        let decoded = ReducedPacket::decode(&packet).unwrap();
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_REDUCED);
        assert_eq!(decoded.gre.version, 1);
        assert_eq!(decoded.gre.sequence, Some(42));
        assert!(decoded.vsf.is_none());
        assert_eq!(decoded.reduced.src_port, 1971);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn reduced_packet_v2_uses_vsf_wrapper_like_librist() {
        let packet = encode_reduced_payload(
            2,
            42,
            ReducedHeader {
                src_port: 1971,
                dst_port: 1968,
            },
            b"payload",
        );
        assert_eq!(&packet[..8], &[0x10, 0x10, 0xcc, 0xe0, 0, 0, 0, 42]);
        assert_eq!(&packet[8..12], &[0, 0, 0, 0]);
        let decoded = ReducedPacket::decode(&packet).unwrap();
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_VSF);
        assert_eq!(decoded.gre.version, 2);
        assert_eq!(decoded.vsf, Some(VsfHeader::rist_reduced()));
        assert_eq!(decoded.reduced.dst_port, 1968);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn keepalive_v1_round_trips() {
        let keepalive = GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]);
        let packet = encode_keepalive_payload(1, 42, keepalive);
        assert_eq!(&packet[..8], &[0x10, 0x08, 0x88, 0xb5, 0, 0, 0, 42]);
        assert_eq!(
            &packet[8..16],
            &[1, 2, 3, 4, 5, 6, 0x25, KEEPALIVE_CAP2_REDUCED_OVERHEAD]
        );

        let decoded = KeepalivePacket::decode(&packet).unwrap();
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_KEEPALIVE);
        assert!(decoded.vsf.is_none());
        assert!(decoded.keepalive.supports_null_packet_deletion());
        assert!(decoded.keepalive.supports_reduced_overhead());
    }

    #[test]
    fn keepalive_v2_uses_vsf_wrapper_like_librist() {
        let keepalive = GreKeepalive {
            json: br#"{"name":"rust"}"#,
            ..GreKeepalive::librist_default([1, 2, 3, 4, 5, 6])
        };
        let packet = encode_keepalive_payload(2, 42, keepalive);
        assert_eq!(&packet[..8], &[0x10, 0x10, 0xcc, 0xe0, 0, 0, 0, 42]);
        assert_eq!(&packet[8..12], &[0, 0, 0x80, 0]);

        let decoded = KeepalivePacket::decode(&packet).unwrap();
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_VSF);
        assert_eq!(decoded.vsf, Some(VsfHeader::rist_keepalive()));
        assert_eq!(decoded.keepalive.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(decoded.keepalive.json, br#"{"name":"rust"}"#);
    }

    #[test]
    fn buffer_negotiation_uses_vsf_wrapper_like_librist() {
        let packet = encode_buffer_negotiation_payload(42, BufferNegotiation::session(1000, 250));
        assert_eq!(&packet[..8], &[0x10, 0x10, 0xcc, 0xe0, 0, 0, 0, 42]);
        assert_eq!(&packet[8..12], &[0, 0, 0x80, 0x02]);
        assert_eq!(&packet[12..18], &[0x03, 0xe8, 0, 0xfa, 0, 0]);

        let decoded = BufferNegotiationPacket::decode(&packet).unwrap();
        assert_eq!(decoded.vsf, VsfHeader::rist_buffer_negotiation());
        assert_eq!(decoded.negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(decoded.negotiation.receiver_current_buffer_ms, 250);
        assert_eq!(decoded.negotiation.protocol_type, 0);
        assert!(decoded.negotiation.protocol_data.is_empty());
    }

    #[test]
    fn buffer_negotiation_keeps_protocol_scoped_data() {
        let negotiation = BufferNegotiation {
            sender_max_buffer_ms: 1000,
            receiver_current_buffer_ms: 250,
            protocol_type: GRE_PROTOCOL_TYPE_REDUCED,
            protocol_data: &[0x07, 0xb3, 0x07, 0xb0],
        };
        let packet = encode_buffer_negotiation_payload(42, negotiation);
        let decoded = BufferNegotiationPacket::decode(&packet).unwrap();
        assert_eq!(decoded.negotiation.protocol_type, GRE_PROTOCOL_TYPE_REDUCED);
        assert_eq!(decoded.negotiation.protocol_data, &[0x07, 0xb3, 0x07, 0xb0]);
    }

    #[test]
    fn encrypted_reduced_packet_round_trips() {
        let mut tx_key = PskKey::from_nonce(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let mut rx_key = PskKey::receiver(256, b"secret").unwrap();
        let packet = encode_encrypted_reduced_payload(
            2,
            42,
            ReducedHeader {
                src_port: 1971,
                dst_port: 1968,
            },
            &rtp(1, b"payload"),
            &mut tx_key,
        );
        assert_eq!(
            &packet[..12],
            &[0x30, 0x50, 0xcc, 0xe0, 1, 2, 3, 4, 0, 0, 0, 42]
        );
        assert_ne!(
            &packet[12..],
            &[0, 0, 0, 0, 0x07, 0xb3, 0x07, 0xb0, b'p'][..]
        );

        let decoded = decode_encrypted_reduced_packet(&packet, &mut rx_key).unwrap();
        assert_eq!(decoded.gre.sequence, Some(42));
        assert_eq!(decoded.gre.key, Some(0x0102_0304));
        assert_eq!(decoded.vsf, Some(VsfHeader::rist_reduced()));
        assert_eq!(decoded.reduced.src_port, 1971);
        assert_eq!(decoded.reduced.dst_port, 1968);
        assert_eq!(decoded.payload, rtp(1, b"payload"));
    }

    #[test]
    fn encrypted_keepalive_packet_round_trips() {
        let mut tx_key = PskKey::from_nonce(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let mut rx_key = PskKey::receiver(256, b"secret").unwrap();
        let keepalive = GreKeepalive {
            mac: [1, 2, 3, 4, 5, 6],
            capabilities1: KEEPALIVE_CAP1_NULL_PACKET_DELETION,
            capabilities2: KEEPALIVE_CAP2_REDUCED_OVERHEAD,
            json: br#"{"peer":"rust"}"#,
        };
        let packet = encode_encrypted_keepalive_payload(2, 42, keepalive, &mut tx_key);

        let (gre, _) = GreHeader::decode(&packet).unwrap();
        assert_eq!(gre.key, Some(0x0102_0304));
        assert_eq!(gre.sequence, Some(42));
        assert!(KeepalivePacket::decode(&packet).is_err());

        let decoded = decode_encrypted_keepalive_packet(&packet, &mut rx_key).unwrap();
        assert_eq!(decoded.gre.sequence, Some(42));
        assert_eq!(decoded.vsf, Some(VsfHeader::rist_keepalive()));
        assert_eq!(decoded.keepalive.mac, [1, 2, 3, 4, 5, 6]);
        assert!(decoded.keepalive.supports_null_packet_deletion());
        assert!(decoded.keepalive.supports_reduced_overhead());
        assert_eq!(decoded.keepalive.json, br#"{"peer":"rust"}"#);
    }

    #[test]
    fn encrypted_buffer_negotiation_packet_round_trips() {
        let mut tx_key = PskKey::from_nonce(128, 0, b"secret", [5, 6, 7, 8]).unwrap();
        let mut rx_key = PskKey::receiver(128, b"secret").unwrap();
        let negotiation = BufferNegotiation {
            sender_max_buffer_ms: 1000,
            receiver_current_buffer_ms: 250,
            protocol_type: 7,
            protocol_data: b"data",
        };
        let packet = encode_encrypted_buffer_negotiation_payload(77, negotiation, &mut tx_key);

        let (gre, _) = GreHeader::decode(&packet).unwrap();
        assert_eq!(gre.key, Some(0x0506_0708));
        assert_eq!(gre.sequence, Some(77));
        assert!(BufferNegotiationPacket::decode(&packet).is_err());

        let decoded = decode_encrypted_buffer_negotiation_packet(&packet, &mut rx_key).unwrap();
        assert_eq!(decoded.gre.sequence, Some(77));
        assert_eq!(decoded.vsf, VsfHeader::rist_buffer_negotiation());
        assert_eq!(decoded.negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(decoded.negotiation.receiver_current_buffer_ms, 250);
        assert_eq!(decoded.negotiation.protocol_type, 7);
        assert_eq!(decoded.negotiation.protocol_data, b"data");
    }

    #[test]
    fn eapol_packet_round_trips_without_vsf_or_encryption() {
        let eap = EapPacket::identity_response(9, b"rist");
        let frame = EapolFrame::eap(EAPOL_VERSION_3, &eap).unwrap();
        let packet = encode_eapol_payload(2, 88, &frame).unwrap();

        assert_eq!(&packet[..8], &[0x10, 0x10, 0x88, 0x8e, 0, 0, 0, 88]);
        let decoded = decode_eapol_payload(&packet).unwrap();
        assert_eq!(decoded.gre.protocol_type, GRE_PROTOCOL_TYPE_EAPOL);
        assert_eq!(decoded.gre.sequence, Some(88));
        assert_eq!(decoded.frame.version, EAPOL_VERSION_3);
        let eap = decoded.frame.eap_packet().unwrap();
        assert_eq!(eap.eap_type, Some(EAP_TYPE_IDENTITY));
        assert_eq!(eap.data, b"rist");
    }

    #[test]
    fn main_datagram_decoder_returns_typed_clear_and_encrypted_events() {
        let reduced = ReducedHeader {
            src_port: 1000,
            dst_port: 2000,
        };
        let clear = encode_reduced_payload(2, 7, reduced, b"media");
        assert!(matches!(
            decode_main_packet(&clear, None).unwrap(),
            MainPacket::Reduced(OwnedReducedPacket { payload, .. }) if payload == b"media"
        ));

        let mut tx = PskKey::from_nonce(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let mut rx = PskKey::receiver(256, b"secret").unwrap();
        let secure = rtp(8, b"secure");
        let encrypted = encode_encrypted_reduced_payload(2, 8, reduced, &secure, &mut tx);
        assert!(matches!(
            decode_main_packet(&encrypted, Some(&mut rx)).unwrap(),
            MainPacket::Reduced(OwnedReducedPacket { payload, .. }) if payload == secure
        ));

        let clear_oob = encode_oob_payload(2, 9, b"tunnel");
        assert!(matches!(
            decode_main_packet(&clear_oob, None).unwrap(),
            MainPacket::Oob(OwnedOobPacket { payload, .. }) if payload == b"tunnel"
        ));

        let mut oob_tx = PskKey::from_nonce(256, 0, b"secret", [5, 6, 7, 8]).unwrap();
        let mut oob_rx = PskKey::receiver(256, b"secret").unwrap();
        let encrypted_oob = encode_encrypted_oob_payload(2, 10, b"secure tunnel", &mut oob_tx);
        assert!(matches!(
            decode_main_packet(&encrypted_oob, Some(&mut oob_rx)).unwrap(),
            MainPacket::Oob(OwnedOobPacket { payload, .. }) if payload == b"secure tunnel"
        ));

        let unknown = GreHeader {
            protocol_type: 0x1234,
            version: 1,
            key: None,
            sequence: Some(9),
        };
        let mut bytes = Vec::new();
        unknown.encode(&mut bytes);
        bytes.extend_from_slice(b"opaque");
        assert!(matches!(
            decode_main_packet(&bytes, None).unwrap(),
            MainPacket::Unknown { payload, .. } if payload == b"opaque"
        ));
    }

    #[test]
    fn main_datagram_decoder_matches_the_borrowed_reduced_decoder() {
        let reduced = ReducedHeader {
            src_port: 1971,
            dst_port: 1968,
        };
        for version in [0, 1, 2] {
            let clear = encode_reduced_payload(version, 70_000, reduced, b"ts-payload");
            let borrowed = ReducedPacket::decode(&clear).unwrap();
            assert_eq!(
                decode_main_packet(&clear, None).unwrap(),
                MainPacket::Reduced(OwnedReducedPacket {
                    gre: borrowed.gre,
                    vsf: borrowed.vsf,
                    reduced,
                    payload: b"ts-payload".to_vec(),
                })
            );
            let mut tx = PskKey::from_nonce(128, 0, b"secret", [9, 9, 9, version]).unwrap();
            let mut rx = PskKey::receiver(128, b"secret").unwrap();
            let secure = rtp(5, b"secure");
            let encrypted = encode_encrypted_reduced_payload(version, 5, reduced, &secure, &mut tx);
            match decode_main_packet(&encrypted, Some(&mut rx)).unwrap() {
                MainPacket::Reduced(packet) => {
                    assert_eq!(packet.reduced, reduced);
                    assert_eq!(packet.vsf.is_some(), version >= 2);
                    assert_eq!(packet.payload, secure);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // A truncated reduced header is still an error, not a silent drop.
        let mut short = encode_reduced_payload(1, 1, reduced, b"");
        short.truncate(short.len() - 1);
        assert!(decode_main_packet(&short, None).is_err());
    }

    fn psk_pair(nonce: [u8; 4]) -> (PskKey, PskKey) {
        (
            PskKey::from_nonce(128, 0, b"12345678", nonce).unwrap(),
            PskKey::receiver(128, b"12345678").unwrap(),
        )
    }

    fn librist_reduced() -> ReducedHeader {
        ReducedHeader {
            src_port: 32_769,
            dst_port: 1968,
        }
    }

    /// Seven MPEG-TS packets, as librist and rist-rs send a data packet.
    fn ts_payload() -> Vec<u8> {
        let mut payload = Vec::with_capacity(7 * 188);
        for index in 0..7u8 {
            let mut packet = vec![0xffu8; 188];
            packet[0] = 0x47;
            packet[1] = 0x01;
            packet[2] = index;
            payload.extend_from_slice(&packet);
        }
        payload
    }

    fn sr_sdes_compound(ssrc: u32) -> Vec<u8> {
        let mut out = Vec::new();
        crate::packet::rtcp::encode_sender_report(
            crate::packet::rtcp::SenderReport {
                ssrc,
                ntp_timestamp: 0x0102_0304_0506_0708,
                rtp_timestamp: 90_000,
                sender_packets: 10,
                sender_bytes: 13_160,
            },
            &mut out,
        );
        crate::packet::rtcp::encode_sdes_cname(ssrc, "librist", &mut out);
        out
    }

    /// With a key, everything but EAPOL must arrive encrypted: clear data,
    /// RTCP, keepalive, buffer negotiation and out-of-band packets are
    /// dropped and counted, as librist ignores clear packets when keyed.
    #[test]
    fn keyed_decoder_drops_every_clear_packet_but_eapol() {
        let (_, mut rx) = psk_pair([1, 2, 3, 4]);
        let reduced = librist_reduced();
        let clear_packets = [
            encode_reduced_payload(1, 1, reduced, &rtp(1, b"data")),
            encode_reduced_payload(2, 2, reduced, &rtp(2, b"data")),
            encode_reduced_payload(2, 3, reduced, &sr_sdes_compound(0x1122_3344)),
            encode_keepalive_payload(1, 4, GreKeepalive::librist_default([1, 2, 3, 4, 5, 6])),
            encode_keepalive_payload(2, 5, GreKeepalive::librist_default([1, 2, 3, 4, 5, 6])),
            encode_buffer_negotiation_payload(6, BufferNegotiation::session(1000, 0)),
            encode_oob_payload(2, 7, b"tunnel"),
        ];
        for (index, packet) in clear_packets.iter().enumerate() {
            assert_eq!(
                decode_main_packet(packet, Some(&mut rx)).unwrap_err(),
                Error::ClearPacketWithPsk,
                "packet {index}"
            );
            assert_eq!(
                rx.receive_counters().clear_packets_dropped,
                index as u64 + 1
            );
        }
        // The typed decoders refuse them too.
        assert_eq!(
            decode_encrypted_reduced_packet(&clear_packets[0], &mut rx).unwrap_err(),
            Error::ClearPacketWithPsk
        );
        assert_eq!(
            decode_encrypted_keepalive_packet(&clear_packets[3], &mut rx).unwrap_err(),
            Error::ClearPacketWithPsk
        );
        assert_eq!(
            decode_encrypted_buffer_negotiation_packet(&clear_packets[5], &mut rx).unwrap_err(),
            Error::ClearPacketWithPsk
        );
        // A key field without a sequence is not an encrypted packet either.
        let mut keyed_no_sequence = Vec::new();
        GreHeader {
            protocol_type: GRE_PROTOCOL_TYPE_REDUCED,
            version: 1,
            key: Some(0x0102_0304),
            sequence: None,
        }
        .encode(&mut keyed_no_sequence);
        keyed_no_sequence.extend_from_slice(&[0; 20]);
        assert_eq!(
            decode_main_packet(&keyed_no_sequence, Some(&mut rx)).unwrap_err(),
            Error::ClearPacketWithPsk
        );
        let dropped = rx.receive_counters().clear_packets_dropped;
        assert_eq!(dropped, clear_packets.len() as u64 + 4);

        // EAPOL stays clear: SRP needs it.
        let eap = EapPacket::identity_response(9, b"rist");
        let frame = EapolFrame::eap(EAPOL_VERSION_3, &eap).unwrap();
        let eapol = encode_eapol_payload(2, 88, &frame).unwrap();
        assert!(matches!(
            decode_main_packet(&eapol, Some(&mut rx)).unwrap(),
            MainPacket::Eapol(EapolGrePacket { frame: decoded, .. }) if decoded == frame
        ));
        assert_eq!(rx.receive_counters().clear_packets_dropped, dropped);
        assert_eq!(rx.receive_counters().decrypt_rejected, 0);
    }

    #[test]
    fn decrypted_checks_accept_what_librist_and_rist_rs_send() {
        let reduced = {
            let mut out = Vec::new();
            librist_reduced().encode(&mut out);
            out
        };
        let with_reduced = |body: &[u8]| {
            let mut out = reduced.clone();
            out.extend_from_slice(body);
            out
        };
        let data = with_reduced(&rtp(7, &ts_payload()));
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &data),
            DecryptVerdict::Strong
        );
        let npd = crate::packet::rtp::encode_packet_with_extension(
            RtpHeader::new_mpegts(8, 90_000, 0x1122_3345),
            crate::packet::rtp::RistRtpExtension::new_npd(0x40),
            &ts_payload()[..188 * 6],
        );
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &with_reduced(&npd)),
            DecryptVerdict::Strong
        );
        let rtcp = with_reduced(&sr_sdes_compound(0x1122_3344));
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &rtcp),
            DecryptVerdict::Strong
        );
        let nack = crate::packet::rtcp::encode_nack_compound(
            crate::packet::rtcp::NackMode::Range,
            0x1122_3344,
            "rust",
            &[3, 4, 9],
        );
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &with_reduced(&nack)),
            DecryptVerdict::Strong
        );
        let mut vsf_data = Vec::new();
        VsfHeader::rist_reduced().encode(&mut vsf_data);
        vsf_data.extend_from_slice(&data);
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_VSF, &vsf_data),
            DecryptVerdict::Strong
        );
        let mut keepalive = Vec::new();
        GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]).encode(&mut keepalive);
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_KEEPALIVE, &keepalive),
            DecryptVerdict::Weak
        );
        let mut json_keepalive = keepalive.clone();
        json_keepalive.extend_from_slice(br#"{"peer":"rust"}"#);
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_KEEPALIVE, &json_keepalive),
            DecryptVerdict::Weak
        );
        let mut negotiation = Vec::new();
        VsfHeader::rist_buffer_negotiation().encode(&mut negotiation);
        BufferNegotiation::session(1000, 0).encode(&mut negotiation);
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_VSF, &negotiation),
            DecryptVerdict::Weak
        );
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_FULL, b"opaque"),
            DecryptVerdict::Weak
        );
    }

    #[test]
    fn decrypted_checks_reject_what_is_not_a_rist_packet() {
        let reduced = [0x80, 0x01, 0x07, 0xb0];
        let with_reduced = |body: &[u8]| {
            let mut out = reduced.to_vec();
            out.extend_from_slice(body);
            out
        };
        let good = rtp(7, b"payload");
        let mutate = |at: usize, value: u8| {
            let mut bad = good.clone();
            bad[at] = value;
            with_reduced(&bad)
        };
        for (name, packet) in [
            ("RTP version 1", mutate(0, 0x40)),
            ("padding", mutate(0, 0xa0)),
            ("CSRC count", mutate(0, 0x81)),
            ("payload type", mutate(1, 0x60)),
            ("extension without RI", mutate(0, 0x90)),
            ("short RTP header", with_reduced(&good[..11])),
            ("no RTP at all", reduced.to_vec()),
        ] {
            assert_eq!(
                check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &packet),
                DecryptVerdict::Bad,
                "{name}"
            );
        }
        let compound = sr_sdes_compound(0x1122_3344);
        let mut trailing = compound.clone();
        trailing.extend_from_slice(&[0; 3]);
        let mut long_length = compound.clone();
        long_length[3] += 1;
        let mut bad_second = compound.clone();
        bad_second[28] = 0x40;
        for (name, packet) in [
            ("RTCP trailing bytes", trailing),
            ("RTCP length past the end", long_length),
            ("RTCP second packet version", bad_second),
            ("RTCP truncated", compound[..30].to_vec()),
        ] {
            assert_eq!(
                check_decrypted(GRE_PROTOCOL_TYPE_REDUCED, &with_reduced(&packet)),
                DecryptVerdict::Bad,
                "{name}"
            );
        }
        let mut vsf = vec![0, 1, 0, 0];
        vsf.extend_from_slice(&with_reduced(&good));
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_VSF, &vsf),
            DecryptVerdict::Bad,
            "VSF protocol"
        );
        for subtype in [0x0001u16, VSF_SUBTYPE_FUTURE_NONCE, 0x8003] {
            let mut vsf = vec![0, 0];
            vsf.extend_from_slice(&subtype.to_be_bytes());
            vsf.extend_from_slice(&with_reduced(&good));
            assert_eq!(
                check_decrypted(GRE_PROTOCOL_TYPE_VSF, &vsf),
                DecryptVerdict::Bad,
                "VSF subtype {subtype:#06x}"
            );
        }
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_KEEPALIVE, &[0; 7]),
            DecryptVerdict::Bad
        );
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_KEEPALIVE, &[7; 8 + 9]),
            DecryptVerdict::Bad
        );
        assert_eq!(
            check_decrypted(GRE_PROTOCOL_TYPE_EAPOL, &with_reduced(&good)),
            DecryptVerdict::Bad
        );
    }

    /// The root cause of the wrong-secret payload: a librist sender starts
    /// at GRE version 1 (reduced, no VSF header), so a wrong passphrase
    /// decrypts its data to a random reduced header and RTP header, and
    /// the only checks on the way to delivery were the RTP version (2 of 8
    /// bits) and the payload type (7 bits): about one packet in 512 got
    /// through, under any SSRC (which made a new flow). The checks now
    /// pass about one in 2^15.
    #[test]
    fn wrong_passphrase_garbage_passed_the_old_checks_and_rarely_passes_the_new() {
        const PACKETS: u32 = 1 << 15;
        let nonce = [0x5a, 0x17, 0xc3, 0x09];
        let mut tx = PskKey::from_nonce(128, 0, b"12345678", nonce).unwrap();
        let mut wrong = PskKey::receiver(128, b"wrongpass").unwrap();
        // One TS packet: the checks read only the headers.
        let payload = ts_payload()[..188].to_vec();
        let mut old_accepts = 0u32;
        let mut new_data_accepts = 0u32;
        let mut new_rtcp_accepts = 0u32;
        for sequence in 0..PACKETS {
            let rtp = encode_packet(
                RtpHeader::new_mpegts(sequence as u16, sequence.wrapping_mul(3_000), 0x0dd0_0d00),
                &payload,
            );
            let packet =
                encode_encrypted_reduced_payload(1, sequence, librist_reduced(), &rtp, &mut tx);
            let (gre, offset) = GreHeader::decode(&packet).unwrap();
            assert_eq!(gre.protocol_type, GRE_PROTOCOL_TYPE_REDUCED);
            let garbage = wrong
                .decrypt(nonce, gre.version, sequence, &packet[offset..])
                .unwrap();
            // The old path: ReducedPacket, then RtpPacket::decode (version
            // 2, CSRC length) and the MPEG-TS payload type, then delivery.
            let old = ReducedPacket::decode_after_gre(gre, &garbage).is_ok_and(|reduced| {
                crate::packet::rtp::RtpPacket::decode(reduced.payload).is_ok_and(|rtp| {
                    rtp.header.payload_type == crate::packet::rtp::RTP_PAYLOAD_TYPE_MPEGTS
                })
            });
            old_accepts += u32::from(old);
            if check_decrypted(gre.protocol_type, &garbage) == DecryptVerdict::Strong {
                if (72..=77).contains(&(garbage[5] & 0x7f)) {
                    new_rtcp_accepts += 1;
                } else {
                    new_data_accepts += 1;
                }
            }
        }
        eprintln!(
            "{PACKETS} wrong-key packets: old checks passed {old_accepts}, new checks passed \
             {new_data_accepts} as data and {new_rtcp_accepts} as RTCP"
        );
        // Expected about PACKETS / 1024 = 32 (version, payload type and a
        // parseable extension when its bit is set) and PACKETS / 32768 = 1.
        assert!(old_accepts >= 16, "old checks passed {old_accepts}");
        assert!(
            new_data_accepts <= 8,
            "new checks passed {new_data_accepts}"
        );
        assert!(
            new_rtcp_accepts <= 4,
            "new checks passed {new_rtcp_accepts} RTCP"
        );
    }

    /// Many librist-like wrong-passphrase sessions (each a fresh nonce:
    /// keepalives, RTCP and data at GRE version 1, then version 2) through
    /// the keyed decoder: nothing is accepted as data or RTCP. A nonce that
    /// has not passed the checks yet is shut out at its first failure, so
    /// each session costs one decryption that fails; the rest are dropped
    /// undecrypted.
    #[test]
    fn wrong_passphrase_sessions_get_no_packet_through() {
        const SESSIONS: u32 = 200;
        const PACKETS_PER_SESSION: u32 = 50;
        let template = PskKey::receiver(128, b"wrongpass").unwrap();
        // One TS packet: the checks read only the headers.
        let payload = ts_payload()[..188].to_vec();
        let mut accepted = 0u32;
        let mut weak = 0u32;
        let mut total = PskReceiveCountersForTest::default();
        for session in 0..SESSIONS {
            let mut rx = template.fresh_copy();
            let nonce = (0x1000_0001u32.wrapping_mul(session + 1) | 1).to_be_bytes();
            let mut tx = PskKey::from_nonce(128, 0, b"12345678", nonce).unwrap();
            let ssrc = 0x2000_0000 | (session << 1);
            for index in 0..PACKETS_PER_SESSION {
                let version = if index < PACKETS_PER_SESSION / 2 {
                    1
                } else {
                    2
                };
                let sequence = index;
                let packet = match (session + index) % 6 {
                    0 => encode_encrypted_keepalive_payload(
                        version,
                        sequence,
                        GreKeepalive::librist_default([2, 0, 0, 0, 0, 1]),
                        &mut tx,
                    ),
                    1 => encode_encrypted_reduced_payload(
                        version,
                        sequence,
                        librist_reduced(),
                        &sr_sdes_compound(ssrc),
                        &mut tx,
                    ),
                    _ => encode_encrypted_reduced_payload(
                        version,
                        sequence,
                        librist_reduced(),
                        &encode_packet(
                            RtpHeader::new_mpegts(index as u16, index * 3_000, ssrc),
                            &payload,
                        ),
                        &mut tx,
                    ),
                };
                match decode_main_packet(&packet, Some(&mut rx)) {
                    Ok(MainPacket::Reduced(_)) => accepted += 1,
                    Ok(_) => weak += 1,
                    Err(_) => {}
                }
            }
            total.add(rx.receive_counters());
        }
        eprintln!(
            "{} wrong-key packets in {SESSIONS} sessions: {accepted} accepted, {weak} keepalives \
             passed, {} rejected, {} dropped by the latch",
            SESSIONS * PACKETS_PER_SESSION,
            total.0.decrypt_rejected,
            total.0.decrypt_latched
        );
        assert_eq!(accepted, 0);
        assert_eq!(total.0.clear_packets_dropped, 0);
        assert_eq!(total.0.nonce_latches, u64::from(SESSIONS));
        assert_eq!(
            total.0.decrypt_rejected + total.0.decrypt_latched + u64::from(weak),
            u64::from(SESSIONS * PACKETS_PER_SESSION)
        );
    }

    #[derive(Default)]
    struct PskReceiveCountersForTest(crate::crypto::PskReceiveCounters);

    impl PskReceiveCountersForTest {
        fn add(&mut self, counters: crate::crypto::PskReceiveCounters) {
            self.0.add(counters);
        }
    }

    /// With the right passphrase every kind of encrypted packet passes and
    /// nothing is counted.
    #[test]
    fn right_passphrase_passes_every_encrypted_packet_kind() {
        let (mut tx, mut rx) = psk_pair([7, 7, 7, 7]);
        let reduced = librist_reduced();
        for version in [1u8, 2] {
            let packets = [
                encode_encrypted_reduced_payload(
                    version,
                    1,
                    reduced,
                    &rtp(1, &ts_payload()),
                    &mut tx,
                ),
                encode_encrypted_reduced_payload(
                    version,
                    2,
                    reduced,
                    &sr_sdes_compound(0x1122_3344),
                    &mut tx,
                ),
                encode_encrypted_keepalive_payload(
                    version,
                    3,
                    GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
                    &mut tx,
                ),
                encode_encrypted_oob_payload(version, 4, b"tunnel", &mut tx),
            ];
            for packet in packets {
                decode_main_packet(&packet, Some(&mut rx)).unwrap();
            }
        }
        let negotiation = encode_encrypted_buffer_negotiation_payload(
            5,
            BufferNegotiation::session(1000, 0),
            &mut tx,
        );
        decode_main_packet(&negotiation, Some(&mut rx)).unwrap();
        assert_eq!(rx.receive_counters(), Default::default());
    }

    #[test]
    fn gre_header_rejects_routing_and_reserved_flags_and_skips_a_checksum() {
        let mut packet = encode_reduced_payload(1, 9, librist_reduced(), &rtp(9, b"x"));
        let clean = packet.clone();
        packet[0] |= GRE_FLAG_ROUTING;
        assert_eq!(
            GreHeader::decode(&packet).unwrap_err(),
            Error::NonConformantGre
        );
        let mut reserved = clean.clone();
        reserved[1] |= 0x01;
        assert_eq!(
            GreHeader::decode(&reserved).unwrap_err(),
            Error::NonConformantGre
        );
        let mut checksum = clean[..4].to_vec();
        checksum[0] |= GRE_FLAG_CHECKSUM;
        checksum.extend_from_slice(&[0xab, 0xcd, 0, 0]);
        checksum.extend_from_slice(&clean[4..]);
        let (header, offset) = GreHeader::decode(&checksum).unwrap();
        assert_eq!(header.sequence, Some(9));
        assert_eq!(&checksum[offset..], &clean[8..]);
    }
}
