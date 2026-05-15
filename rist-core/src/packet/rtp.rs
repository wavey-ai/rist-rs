use crate::{Error, Result};

pub const RTP_HEADER_LEN: usize = 12;
pub const RTP_EXTENSION_HEADER_LEN: usize = 4;
pub const RIST_RTP_EXTENSION_LEN: usize = 8;
pub const RIST_RTP_EXTENSION_IDENTIFIER: [u8; 2] = *b"RI";
pub const RIST_RTP_EXTENSION_WORDS: u16 = 1;
pub const RIST_RTP_EXTENSION_NPD_FLAG: u8 = 1 << 7;
pub const RTP_VERSION: u8 = 2;
pub const RTP_MPEGTS_FLAGS: u8 = 0x80;
pub const RTP_PAYLOAD_TYPE_MPEGTS: u8 = 0x21;
pub const RTP_PAYLOAD_TYPE_RIST: u8 = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
}

impl RtpHeader {
    pub fn new_mpegts(sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            marker: false,
            payload_type: RTP_PAYLOAD_TYPE_MPEGTS,
            sequence_number,
            timestamp,
            ssrc,
            padding: false,
            extension: false,
            csrc_count: 0,
        }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(
            (RTP_VERSION << 6)
                | ((self.padding as u8) << 5)
                | ((self.extension as u8) << 4)
                | (self.csrc_count & 0x0f),
        );
        out.push(((self.marker as u8) << 7) | (self.payload_type & 0x7f));
        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < RTP_HEADER_LEN {
            return Err(Error::PacketTooShort {
                needed: RTP_HEADER_LEN,
                actual: input.len(),
            });
        }

        let version = input[0] >> 6;
        if version != RTP_VERSION {
            return Err(Error::UnsupportedRtpVersion(version));
        }

        let csrc_count = input[0] & 0x0f;
        let header_len = RTP_HEADER_LEN + usize::from(csrc_count) * 4;
        if input.len() < header_len {
            return Err(Error::PacketTooShort {
                needed: header_len,
                actual: input.len(),
            });
        }

        Ok((
            Self {
                marker: input[1] & 0x80 != 0,
                payload_type: input[1] & 0x7f,
                sequence_number: u16::from_be_bytes([input[2], input[3]]),
                timestamp: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                ssrc: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
                padding: input[0] & 0x20 != 0,
                extension: input[0] & 0x10 != 0,
                csrc_count,
            },
            header_len,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RistRtpExtension {
    pub flags: u8,
    pub npd_bits: u8,
    pub sequence_extension: u16,
}

impl RistRtpExtension {
    pub fn new_npd(npd_bits: u8) -> Self {
        Self {
            flags: RIST_RTP_EXTENSION_NPD_FLAG,
            npd_bits,
            sequence_extension: 0,
        }
    }

    pub fn has_null_packet_deletion(self) -> bool {
        self.flags & RIST_RTP_EXTENSION_NPD_FLAG != 0
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&RIST_RTP_EXTENSION_IDENTIFIER);
        out.extend_from_slice(&RIST_RTP_EXTENSION_WORDS.to_be_bytes());
        out.push(self.flags);
        out.push(self.npd_bits);
        out.extend_from_slice(&self.sequence_extension.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub header: RtpHeader,
    pub extension: Option<RistRtpExtension>,
    pub payload: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        let (header, mut payload_offset) = RtpHeader::decode(input)?;
        let extension = if header.extension {
            if input.len() < payload_offset + RTP_EXTENSION_HEADER_LEN {
                return Err(Error::PacketTooShort {
                    needed: payload_offset + RTP_EXTENSION_HEADER_LEN,
                    actual: input.len(),
                });
            }

            let identifier = [input[payload_offset], input[payload_offset + 1]];
            let length_words =
                u16::from_be_bytes([input[payload_offset + 2], input[payload_offset + 3]]);
            let extension_payload_len = usize::from(length_words) * 4;
            let extension_end = payload_offset + RTP_EXTENSION_HEADER_LEN + extension_payload_len;
            if input.len() < extension_end {
                return Err(Error::PacketTooShort {
                    needed: extension_end,
                    actual: input.len(),
                });
            }

            let extension = if identifier == RIST_RTP_EXTENSION_IDENTIFIER
                && length_words == RIST_RTP_EXTENSION_WORDS
                && extension_payload_len >= 4
            {
                let data_offset = payload_offset + RTP_EXTENSION_HEADER_LEN;
                Some(RistRtpExtension {
                    flags: input[data_offset],
                    npd_bits: input[data_offset + 1],
                    sequence_extension: u16::from_be_bytes([
                        input[data_offset + 2],
                        input[data_offset + 3],
                    ]),
                })
            } else {
                None
            };
            payload_offset = extension_end;
            extension
        } else {
            None
        };

        Ok(Self {
            header,
            extension,
            payload: &input[payload_offset..],
        })
    }
}

pub fn encode_packet(header: RtpHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RTP_HEADER_LEN + payload.len());
    header.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

pub fn encode_packet_with_extension(
    mut header: RtpHeader,
    extension: RistRtpExtension,
    payload: &[u8],
) -> Vec<u8> {
    header.extension = true;
    let mut out = Vec::with_capacity(RTP_HEADER_LEN + RIST_RTP_EXTENSION_LEN + payload.len());
    header.encode(&mut out);
    extension.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_librist_mpegts_header_shape() {
        let bytes = encode_packet(
            RtpHeader::new_mpegts(0x1234, 0x0102_0304, 0xaabb_ccdd),
            b"abc",
        );
        assert_eq!(
            &bytes[..12],
            &[0x80, 0x21, 0x12, 0x34, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd]
        );
        let decoded = RtpPacket::decode(&bytes).unwrap();
        assert_eq!(decoded.header.sequence_number, 0x1234);
        assert_eq!(decoded.extension, None);
        assert_eq!(decoded.payload, b"abc");
    }

    #[test]
    fn rist_header_extension_round_trips() {
        let bytes = encode_packet_with_extension(
            RtpHeader::new_mpegts(0x1234, 0x0102_0304, 0xaabb_ccdd),
            RistRtpExtension::new_npd(0x20),
            b"abc",
        );
        assert_eq!(bytes[0], 0x90);
        assert_eq!(&bytes[12..20], &[b'R', b'I', 0, 1, 0x80, 0x20, 0, 0]);

        let decoded = RtpPacket::decode(&bytes).unwrap();
        assert_eq!(decoded.header.sequence_number, 0x1234);
        assert_eq!(decoded.payload, b"abc");
        assert_eq!(
            decoded.extension,
            Some(RistRtpExtension {
                flags: RIST_RTP_EXTENSION_NPD_FLAG,
                npd_bits: 0x20,
                sequence_extension: 0
            })
        );
    }

    #[test]
    fn skips_unknown_header_extension() {
        let mut bytes = encode_packet(RtpHeader::new_mpegts(1, 2, 3), b"payload");
        bytes[0] |= 0x10;
        bytes.splice(12..12, [b'U', b'K', 0, 1, 1, 2, 3, 4]);

        let decoded = RtpPacket::decode(&bytes).unwrap();
        assert_eq!(decoded.extension, None);
        assert_eq!(decoded.payload, b"payload");
    }
}
