use crate::{Error, Result};

pub const RTCP_VERSION: u8 = 2;
pub const PTYPE_SR: u8 = 200;
pub const PTYPE_RR: u8 = 201;
pub const PTYPE_SDES: u8 = 202;
pub const PTYPE_NACK_CUSTOM: u8 = 204;
pub const PTYPE_NACK_BITMASK: u8 = 205;
pub const PTYPE_XR: u8 = 77;
pub const RTCP_SR_FLAGS: u8 = 0x80;
pub const RTCP_RR_FULL_FLAGS: u8 = 0x81;
pub const RTCP_SDES_FLAGS: u8 = 0x81;
pub const RTCP_NACK_RANGE_FLAGS: u8 = 0x80;
pub const RTCP_NACK_BITMASK_FLAGS: u8 = 0x81;
pub const RTCP_NACK_SEQEXT_FLAGS: u8 = 0x81;
pub const RTCP_ECHOEXT_REQ_FLAGS: u8 = 0x82;
pub const RTCP_ECHOEXT_RESP_FLAGS: u8 = 0x83;
pub const NACK_FMT_RANGE: u8 = 0;
pub const NACK_FMT_BITMASK: u8 = 1;
pub const NACK_FMT_SEQEXT: u8 = 1;
pub const ECHO_REQUEST: u8 = 2;
pub const ECHO_RESPONSE: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcpHeader {
    pub flags: u8,
    pub packet_type: u8,
    pub length_words_minus_one: u16,
    pub ssrc: u32,
}

impl RtcpHeader {
    pub const LEN: usize = 8;

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::LEN {
            return Err(Error::PacketTooShort {
                needed: Self::LEN,
                actual: input.len(),
            });
        }
        let length_words_minus_one = u16::from_be_bytes([input[2], input[3]]);
        let advertised = (usize::from(length_words_minus_one) + 1) * 4;
        if input.len() < advertised {
            return Err(Error::InvalidRtcpLength {
                advertised,
                actual: input.len(),
            });
        }
        Ok(Self {
            flags: input[0],
            packet_type: input[1],
            length_words_minus_one,
            ssrc: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
        })
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.push(self.packet_type);
        out.extend_from_slice(&self.length_words_minus_one.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
    }

    pub fn packet_len(self) -> usize {
        (usize::from(self.length_words_minus_one) + 1) * 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackMode {
    Range,
    Bitmask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackRecord {
    pub start: u16,
    pub extra: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderReport {
    pub ssrc: u32,
    pub ntp_timestamp: u64,
    pub rtp_timestamp: u32,
    pub sender_packets: u32,
    pub sender_bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverReport {
    pub ssrc: u32,
    pub recv_ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_packet_loss: u32,
    pub highest_sequence: u32,
    pub jitter: u32,
    pub last_sender_report: u32,
    pub delay_since_last_sender_report: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoKind {
    Request,
    Response { delay: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    pub ssrc: u32,
    pub ntp_timestamp: u64,
    pub kind: EchoKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    EmptyReceiverReport { ssrc: u32 },
    SourceDescription { ssrc: u32, cname: String },
    Echo(Echo),
    Nack(Vec<u32>),
    Unknown { packet_type: u8, flags: u8 },
}

pub fn encode_sender_report(report: SenderReport, out: &mut Vec<u8>) {
    RtcpHeader {
        flags: RTCP_SR_FLAGS,
        packet_type: PTYPE_SR,
        length_words_minus_one: 6,
        ssrc: report.ssrc,
    }
    .encode(out);
    out.extend_from_slice(&((report.ntp_timestamp >> 32) as u32).to_be_bytes());
    out.extend_from_slice(&(report.ntp_timestamp as u32).to_be_bytes());
    out.extend_from_slice(&report.rtp_timestamp.to_be_bytes());
    out.extend_from_slice(&report.sender_packets.to_be_bytes());
    out.extend_from_slice(&report.sender_bytes.to_be_bytes());
}

pub fn encode_receiver_report(report: ReceiverReport, out: &mut Vec<u8>) {
    RtcpHeader {
        flags: RTCP_RR_FULL_FLAGS,
        packet_type: PTYPE_RR,
        length_words_minus_one: 7,
        ssrc: report.ssrc,
    }
    .encode(out);
    out.extend_from_slice(&report.recv_ssrc.to_be_bytes());
    out.push(report.fraction_lost);
    let cumulative_loss = report.cumulative_packet_loss & 0x00ff_ffff;
    out.push((cumulative_loss >> 16) as u8);
    out.extend_from_slice(&(cumulative_loss as u16).to_be_bytes());
    out.extend_from_slice(&report.highest_sequence.to_be_bytes());
    out.extend_from_slice(&report.jitter.to_be_bytes());
    out.extend_from_slice(&report.last_sender_report.to_be_bytes());
    out.extend_from_slice(&report.delay_since_last_sender_report.to_be_bytes());
}

pub fn encode_empty_receiver_report(ssrc: u32, out: &mut Vec<u8>) {
    RtcpHeader {
        flags: RTCP_SR_FLAGS,
        packet_type: PTYPE_RR,
        length_words_minus_one: 1,
        ssrc,
    }
    .encode(out);
}

pub fn encode_sdes_cname(ssrc: u32, cname: &str, out: &mut Vec<u8>) {
    let name = cname.as_bytes();
    let sdes_size = ((10 + name.len() + 1) + 3) & !3;
    RtcpHeader {
        flags: RTCP_SDES_FLAGS,
        packet_type: PTYPE_SDES,
        length_words_minus_one: ((sdes_size - 1) >> 2) as u16,
        ssrc,
    }
    .encode(out);
    out.push(1);
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.resize(out.len() + (sdes_size - 10 - name.len()), 0);
}

pub fn encode_echo(echo: Echo, out: &mut Vec<u8>) {
    let flags = match echo.kind {
        EchoKind::Request => RTCP_ECHOEXT_REQ_FLAGS,
        EchoKind::Response { .. } => RTCP_ECHOEXT_RESP_FLAGS,
    };
    RtcpHeader {
        flags,
        packet_type: PTYPE_NACK_CUSTOM,
        length_words_minus_one: 5,
        ssrc: echo.ssrc,
    }
    .encode(out);
    out.extend_from_slice(b"RIST");
    out.extend_from_slice(&((echo.ntp_timestamp >> 32) as u32).to_be_bytes());
    out.extend_from_slice(&(echo.ntp_timestamp as u32).to_be_bytes());
    let delay = match echo.kind {
        EchoKind::Request => 0,
        EchoKind::Response { delay } => delay,
    };
    out.extend_from_slice(&delay.to_be_bytes());
}

pub fn encode_nack(mode: NackMode, flow_id: u32, missing: &[u32], out: &mut Vec<u8>) {
    if missing.is_empty() {
        return;
    }
    let records = match mode {
        NackMode::Range => range_records(missing),
        NackMode::Bitmask => bitmask_records(missing),
    };
    let length_words_minus_one = 2 + records.len() as u16;
    match mode {
        NackMode::Range => {
            out.push(RTCP_NACK_RANGE_FLAGS);
            out.push(PTYPE_NACK_CUSTOM);
            out.extend_from_slice(&length_words_minus_one.to_be_bytes());
            out.extend_from_slice(&flow_id.to_be_bytes());
            out.extend_from_slice(b"RIST");
        }
        NackMode::Bitmask => {
            out.push(RTCP_NACK_BITMASK_FLAGS);
            out.push(PTYPE_NACK_BITMASK);
            out.extend_from_slice(&length_words_minus_one.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&flow_id.to_be_bytes());
        }
    }
    for record in records {
        out.extend_from_slice(&record.start.to_be_bytes());
        out.extend_from_slice(&record.extra.to_be_bytes());
    }
}

pub fn encode_nack_compound(mode: NackMode, flow_id: u32, cname: &str, missing: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_empty_receiver_report(flow_id, &mut out);
    encode_sdes_cname(flow_id, cname, &mut out);
    encode_nack(mode, flow_id, missing, &mut out);
    out
}

pub fn decode_nack(input: &[u8], seq_msb: u32) -> Result<Vec<u32>> {
    let header = RtcpHeader::decode(input)?;
    let payload = &input[..header.packet_len()];
    match header.packet_type {
        PTYPE_NACK_CUSTOM => decode_range_nack(payload, seq_msb),
        PTYPE_NACK_BITMASK => decode_bitmask_nack(payload, seq_msb),
        _ => Ok(Vec::new()),
    }
}

pub fn decode_nacks_from_compound(input: &[u8]) -> Result<Vec<u32>> {
    let mut offset = 0;
    let mut seq_msb = 0;
    let mut out = Vec::new();

    while offset < input.len() {
        if input.len() - offset < 4 {
            return Err(Error::PacketTooShort {
                needed: offset + 4,
                actual: input.len(),
            });
        }
        let header = RtcpHeader::decode(&input[offset..])?;
        let packet_len = header.packet_len();
        let packet_end = offset + packet_len;
        if input.len() < packet_end {
            return Err(Error::InvalidRtcpLength {
                advertised: packet_end,
                actual: input.len(),
            });
        }
        let packet = &input[offset..packet_end];
        let subtype = header.flags & 0x1f;
        if header.packet_type == PTYPE_NACK_CUSTOM && subtype == NACK_FMT_SEQEXT {
            if packet.len() >= 14 {
                seq_msb = u32::from(u16::from_be_bytes([packet[12], packet[13]])) << 16;
            }
        } else if header.packet_type == PTYPE_NACK_CUSTOM
            && (subtype == ECHO_REQUEST || subtype == ECHO_RESPONSE)
        {
            // Echo packets share the custom RTCP packet type but are not NACKs.
        } else {
            out.extend(decode_nack(packet, seq_msb)?);
        }
        offset = packet_end;
    }

    Ok(out)
}

pub fn decode_compound(input: &[u8]) -> Result<Vec<RtcpPacket>> {
    let mut offset = 0;
    let mut seq_msb = 0;
    let mut out = Vec::new();

    while offset < input.len() {
        if input.len() - offset < 4 {
            return Err(Error::PacketTooShort {
                needed: offset + 4,
                actual: input.len(),
            });
        }
        let header = RtcpHeader::decode(&input[offset..])?;
        let packet_len = header.packet_len();
        let packet_end = offset + packet_len;
        if input.len() < packet_end {
            return Err(Error::InvalidRtcpLength {
                advertised: packet_end,
                actual: input.len(),
            });
        }
        let packet = &input[offset..packet_end];
        let subtype = header.flags & 0x1f;
        let decoded = match header.packet_type {
            PTYPE_SR => decode_sender_report(packet)?.map(RtcpPacket::SenderReport),
            PTYPE_RR if header.length_words_minus_one == 1 => {
                Some(RtcpPacket::EmptyReceiverReport { ssrc: header.ssrc })
            }
            PTYPE_RR => decode_receiver_report(packet)?.map(RtcpPacket::ReceiverReport),
            PTYPE_SDES => decode_sdes(packet)?.map(|cname| RtcpPacket::SourceDescription {
                ssrc: header.ssrc,
                cname,
            }),
            PTYPE_NACK_CUSTOM if subtype == NACK_FMT_SEQEXT => {
                if packet.len() >= 14 {
                    seq_msb = u32::from(u16::from_be_bytes([packet[12], packet[13]])) << 16;
                }
                None
            }
            PTYPE_NACK_CUSTOM if subtype == ECHO_REQUEST || subtype == ECHO_RESPONSE => {
                decode_echo(packet)?.map(RtcpPacket::Echo)
            }
            PTYPE_NACK_CUSTOM | PTYPE_NACK_BITMASK => {
                Some(RtcpPacket::Nack(decode_nack(packet, seq_msb)?))
            }
            _ => Some(RtcpPacket::Unknown {
                packet_type: header.packet_type,
                flags: header.flags,
            }),
        };
        if let Some(decoded) = decoded {
            out.push(decoded);
        }
        offset = packet_end;
    }

    Ok(out)
}

fn decode_sender_report(input: &[u8]) -> Result<Option<SenderReport>> {
    let header = RtcpHeader::decode(input)?;
    if header.packet_len() < 28 {
        return Ok(None);
    }
    Ok(Some(SenderReport {
        ssrc: header.ssrc,
        ntp_timestamp: (u64::from(read_u32(input, 8)) << 32) | u64::from(read_u32(input, 12)),
        rtp_timestamp: read_u32(input, 16),
        sender_packets: read_u32(input, 20),
        sender_bytes: read_u32(input, 24),
    }))
}

fn decode_receiver_report(input: &[u8]) -> Result<Option<ReceiverReport>> {
    let header = RtcpHeader::decode(input)?;
    if header.packet_len() < 32 {
        return Ok(None);
    }
    let cumulative_packet_loss =
        (u32::from(input[13]) << 16) | u32::from(u16::from_be_bytes([input[14], input[15]]));
    Ok(Some(ReceiverReport {
        ssrc: header.ssrc,
        recv_ssrc: read_u32(input, 8),
        fraction_lost: input[12],
        cumulative_packet_loss,
        highest_sequence: read_u32(input, 16),
        jitter: read_u32(input, 20),
        last_sender_report: read_u32(input, 24),
        delay_since_last_sender_report: read_u32(input, 28),
    }))
}

fn decode_sdes(input: &[u8]) -> Result<Option<String>> {
    let header = RtcpHeader::decode(input)?;
    if header.packet_len() < 10 || input[8] != 1 {
        return Ok(None);
    }
    let name_len = usize::from(input[9]);
    if input.len() < 10 + name_len {
        return Err(Error::PacketTooShort {
            needed: 10 + name_len,
            actual: input.len(),
        });
    }
    Ok(Some(
        String::from_utf8_lossy(&input[10..10 + name_len]).to_string(),
    ))
}

fn decode_echo(input: &[u8]) -> Result<Option<Echo>> {
    let header = RtcpHeader::decode(input)?;
    if header.packet_len() < 24 || &input[8..12] != b"RIST" {
        return Ok(None);
    }
    let ntp_timestamp = (u64::from(read_u32(input, 12)) << 32) | u64::from(read_u32(input, 16));
    let kind = match header.flags & 0x1f {
        ECHO_REQUEST => EchoKind::Request,
        ECHO_RESPONSE => EchoKind::Response {
            delay: read_u32(input, 20),
        },
        _ => return Ok(None),
    };
    Ok(Some(Echo {
        ssrc: header.ssrc,
        ntp_timestamp,
        kind,
    }))
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn range_records(missing: &[u32]) -> Vec<NackRecord> {
    let mut sorted = missing.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut records = Vec::new();
    let mut iter = sorted.into_iter();
    let Some(first) = iter.next() else {
        return records;
    };
    let mut start = first as u16;
    let mut last = start;
    let mut extra = 0u16;

    for sequence in iter {
        let seq = sequence as u16;
        if extra != u16::MAX && seq == last.wrapping_add(1) {
            extra = extra.wrapping_add(1);
        } else {
            records.push(NackRecord { start, extra });
            start = seq;
            extra = 0;
        }
        last = seq;
    }
    records.push(NackRecord { start, extra });
    records
}

fn bitmask_records(missing: &[u32]) -> Vec<NackRecord> {
    let mut sorted = missing.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut records = Vec::new();
    let mut iter = sorted.into_iter();
    let Some(first) = iter.next() else {
        return records;
    };
    let mut start = first;
    let mut extra = 0u16;
    let mut boundary = start + 16;

    for sequence in iter {
        if start < sequence && sequence <= boundary {
            extra |= 1 << (sequence - start - 1);
        } else {
            records.push(NackRecord {
                start: start as u16,
                extra,
            });
            start = sequence;
            extra = 0;
            boundary = start + 16;
        }
    }
    records.push(NackRecord {
        start: start as u16,
        extra,
    });
    records
}

fn decode_range_nack(input: &[u8], seq_msb: u32) -> Result<Vec<u32>> {
    if input.len() < 12 || &input[8..12] != b"RIST" {
        return Ok(Vec::new());
    }
    let header = RtcpHeader::decode(input)?;
    let record_count = header.length_words_minus_one.saturating_sub(2) as usize;
    decode_records(&input[12..], record_count, seq_msb, NackMode::Range)
}

fn decode_bitmask_nack(input: &[u8], seq_msb: u32) -> Result<Vec<u32>> {
    if input.len() < 12 {
        return Ok(Vec::new());
    }
    let header = RtcpHeader::decode(input)?;
    let record_count = header.length_words_minus_one.saturating_sub(2) as usize;
    decode_records(&input[12..], record_count, seq_msb, NackMode::Bitmask)
}

fn decode_records(
    input: &[u8],
    record_count: usize,
    seq_msb: u32,
    mode: NackMode,
) -> Result<Vec<u32>> {
    let needed = record_count * 4;
    if input.len() < needed {
        return Err(Error::PacketTooShort {
            needed,
            actual: input.len(),
        });
    }

    let mut out = Vec::new();
    for record in input[..needed].chunks_exact(4) {
        let start = u16::from_be_bytes([record[0], record[1]]);
        let extra = u16::from_be_bytes([record[2], record[3]]);
        let base = seq_msb + u32::from(start);
        out.push(base);
        match mode {
            NackMode::Range => {
                for offset in 1..=u32::from(extra) {
                    out.push(base + offset);
                }
            }
            NackMode::Bitmask => {
                for bit in 0..16 {
                    if extra & (1 << bit) != 0 {
                        out.push(base + bit + 1);
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_range_nack_like_librist() {
        let mut out = Vec::new();
        encode_nack(NackMode::Range, 0x1122_3344, &[10, 11, 12, 20], &mut out);
        assert_eq!(
            &out[..12],
            &[0x80, 204, 0, 4, 0x11, 0x22, 0x33, 0x44, b'R', b'I', b'S', b'T']
        );
        assert_eq!(decode_nack(&out, 0).unwrap(), vec![10, 11, 12, 20]);
    }

    #[test]
    fn encodes_bitmask_nack_like_librist() {
        let mut out = Vec::new();
        encode_nack(NackMode::Bitmask, 7, &[10, 12, 26, 40], &mut out);
        assert_eq!(&out[..12], &[0x81, 205, 0, 4, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(decode_nack(&out, 0).unwrap(), vec![10, 12, 26, 40]);
    }

    #[test]
    fn builds_compound_receiver_feedback_prefix() {
        let out = encode_nack_compound(NackMode::Range, 1, "rust", &[4]);
        assert_eq!(&out[..8], &[0x80, 201, 0, 1, 0, 0, 0, 1]);
        assert_eq!(out[8], 0x81);
        assert_eq!(out[9], 202);
        assert_eq!(decode_nacks_from_compound(&out).unwrap(), vec![4]);
        assert_eq!(
            decode_compound(&out).unwrap(),
            vec![
                RtcpPacket::EmptyReceiverReport { ssrc: 1 },
                RtcpPacket::SourceDescription {
                    ssrc: 1,
                    cname: "rust".to_string()
                },
                RtcpPacket::Nack(vec![4])
            ]
        );
    }

    #[test]
    fn sender_report_round_trips() {
        let report = SenderReport {
            ssrc: 7,
            ntp_timestamp: 0x0102_0304_0506_0708,
            rtp_timestamp: 90_000,
            sender_packets: 12,
            sender_bytes: 1316,
        };
        let mut out = Vec::new();
        encode_sender_report(report, &mut out);
        assert_eq!(&out[..8], &[0x80, 200, 0, 6, 0, 0, 0, 7]);
        assert_eq!(
            decode_compound(&out).unwrap(),
            vec![RtcpPacket::SenderReport(report)]
        );
    }

    #[test]
    fn receiver_report_round_trips() {
        let report = ReceiverReport {
            ssrc: 1,
            recv_ssrc: 2,
            fraction_lost: 3,
            cumulative_packet_loss: 4,
            highest_sequence: 5,
            jitter: 6,
            last_sender_report: 7,
            delay_since_last_sender_report: 8,
        };
        let mut out = Vec::new();
        encode_receiver_report(report, &mut out);
        assert_eq!(&out[..8], &[0x81, 201, 0, 7, 0, 0, 0, 1]);
        assert_eq!(
            decode_compound(&out).unwrap(),
            vec![RtcpPacket::ReceiverReport(report)]
        );
    }

    #[test]
    fn echo_request_and_response_round_trip() {
        let request = Echo {
            ssrc: 9,
            ntp_timestamp: 0x0102_0304_0506_0708,
            kind: EchoKind::Request,
        };
        let response = Echo {
            ssrc: 9,
            ntp_timestamp: request.ntp_timestamp,
            kind: EchoKind::Response { delay: 123 },
        };
        let mut out = Vec::new();
        encode_echo(request, &mut out);
        encode_echo(response, &mut out);
        assert_eq!(&out[..8], &[0x82, 204, 0, 5, 0, 0, 0, 9]);
        assert_eq!(
            decode_compound(&out).unwrap(),
            vec![RtcpPacket::Echo(request), RtcpPacket::Echo(response)]
        );
    }
}
