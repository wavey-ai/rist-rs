use crate::crypto::{AesKeySize, PskKey};
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
        let version = (input[1] >> 3) & 0x07;
        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        let mut offset = Self::MIN_LEN;
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
        let (gre, mut offset) = GreHeader::decode(input)?;
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
        let (gre, mut offset) = GreHeader::decode(input)?;
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

pub fn decode_encrypted_reduced_packet(
    input: &[u8],
    key: &mut PskKey,
) -> Result<OwnedReducedPacket> {
    let (gre, offset) = GreHeader::decode(input)?;
    let Some(nonce) = gre.key else {
        return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
    };
    let Some(sequence) = gre.sequence else {
        return Err(Error::UnsupportedGreProtocol(gre.protocol_type));
    };
    let decrypted = key.decrypt(nonce.to_be_bytes(), gre.version, sequence, &input[offset..]);
    let packet = ReducedPacket::decode_after_gre(gre, &decrypted)?;
    Ok(OwnedReducedPacket {
        gre: packet.gre,
        vsf: packet.vsf,
        reduced: packet.reduced,
        payload: packet.payload.to_vec(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut tx_key = PskKey::new(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let mut rx_key = PskKey::new(256, 0, b"secret", [0, 0, 0, 0]).unwrap();
        let packet = encode_encrypted_reduced_payload(
            2,
            42,
            ReducedHeader {
                src_port: 1971,
                dst_port: 1968,
            },
            b"payload",
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
        assert_eq!(decoded.payload, b"payload");
    }
}
