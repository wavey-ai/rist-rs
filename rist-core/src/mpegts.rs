use crate::{Error, Result};

pub const TS_PACKET_SIZE: usize = 188;
pub const TS_PACKET_SIZE_WITH_RS: usize = 204;
pub const TS_SYNC_BYTE: u8 = 0x47;
pub const TS_NULL_PID: u16 = 0x1fff;
pub const NPD_PACKET_SIZE_204_BIT: u8 = 1 << 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullPacketSuppression {
    pub payload: Vec<u8>,
    pub npd_bits: u8,
    pub bytes_suppressed: usize,
    pub packet_size: usize,
}

pub fn suppress_null_packets(payload: &[u8]) -> Result<NullPacketSuppression> {
    let packet_size = packet_size(payload)?;
    let count = payload.len() / packet_size;
    if count > 7 {
        return Err(Error::InvalidMpegTsLength(payload.len()));
    }
    if payload.first().copied() != Some(TS_SYNC_BYTE) {
        return Err(Error::InvalidMpegTsSync(
            payload.first().copied().unwrap_or(0),
        ));
    }

    let mut npd_bits = if packet_size == TS_PACKET_SIZE_WITH_RS {
        NPD_PACKET_SIZE_204_BIT
    } else {
        0
    };
    let mut out = Vec::with_capacity(payload.len());
    let mut suppressed = 0usize;

    for index in 0..count {
        let offset = index * packet_size;
        let packet = &payload[offset..offset + packet_size];
        if packet[0] != TS_SYNC_BYTE {
            return Err(Error::InvalidMpegTsSync(packet[0]));
        }
        if is_null_packet(packet) {
            npd_bits |= 1 << (6 - index);
            suppressed += 1;
        } else {
            out.extend_from_slice(packet);
        }
    }

    if suppressed == 0 {
        out.clear();
        out.extend_from_slice(payload);
    }

    Ok(NullPacketSuppression {
        payload: out,
        npd_bits,
        bytes_suppressed: suppressed * packet_size,
        packet_size,
    })
}

pub fn expand_null_packets(payload: &[u8], npd_bits: u8) -> Result<Vec<u8>> {
    let packet_size = if npd_bits & NPD_PACKET_SIZE_204_BIT == 0 {
        TS_PACKET_SIZE
    } else {
        TS_PACKET_SIZE_WITH_RS
    };
    if payload.len() % packet_size != 0 {
        return Err(Error::InvalidMpegTsLength(payload.len()));
    }

    let null_count = (0..7)
        .filter(|index| npd_bits & (1 << (6 - index)) != 0)
        .count();
    if null_count == 0 {
        return Ok(payload.to_vec());
    }

    let total_packets = payload.len() / packet_size + null_count;
    if total_packets > 7 {
        return Err(Error::InvalidMpegTsLength(total_packets * packet_size));
    }

    let mut out = Vec::with_capacity(total_packets * packet_size);
    let mut input_offset = 0;
    for index in 0..total_packets {
        if npd_bits & (1 << (6 - index)) != 0 {
            append_null_packet(&mut out, packet_size);
        } else {
            let end = input_offset + packet_size;
            if payload.len() < end {
                return Err(Error::InvalidMpegTsLength(payload.len()));
            }
            out.extend_from_slice(&payload[input_offset..end]);
            input_offset = end;
        }
    }
    Ok(out)
}

pub fn is_null_packet(packet: &[u8]) -> bool {
    packet.len() >= 4
        && packet[0] == TS_SYNC_BYTE
        && u16::from_be_bytes([packet[1], packet[2]]) == TS_NULL_PID
}

fn packet_size(payload: &[u8]) -> Result<usize> {
    if !payload.is_empty() && payload.len() % TS_PACKET_SIZE == 0 {
        Ok(TS_PACKET_SIZE)
    } else if !payload.is_empty() && payload.len() % TS_PACKET_SIZE_WITH_RS == 0 {
        Ok(TS_PACKET_SIZE_WITH_RS)
    } else {
        Err(Error::InvalidMpegTsLength(payload.len()))
    }
}

fn append_null_packet(out: &mut Vec<u8>, packet_size: usize) {
    out.push(TS_SYNC_BYTE);
    out.extend_from_slice(&TS_NULL_PID.to_be_bytes());
    out.push(0x10);
    out.resize(out.len() + packet_size - 4, 0xff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppresses_and_expands_188_byte_null_packets() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&packet(0x1111, b"first", TS_PACKET_SIZE));
        payload.extend_from_slice(&packet(TS_NULL_PID, b"", TS_PACKET_SIZE));
        payload.extend_from_slice(&packet(0x1112, b"third", TS_PACKET_SIZE));

        let suppressed = suppress_null_packets(&payload).unwrap();
        assert_eq!(suppressed.bytes_suppressed, TS_PACKET_SIZE);
        assert_eq!(suppressed.npd_bits, 1 << 5);
        assert_eq!(suppressed.payload.len(), TS_PACKET_SIZE * 2);

        let expanded = expand_null_packets(&suppressed.payload, suppressed.npd_bits).unwrap();
        assert_eq!(expanded, payload);
    }

    #[test]
    fn suppresses_and_expands_204_byte_null_packets() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&packet(TS_NULL_PID, b"", TS_PACKET_SIZE_WITH_RS));
        payload.extend_from_slice(&packet(0x1111, b"data", TS_PACKET_SIZE_WITH_RS));

        let suppressed = suppress_null_packets(&payload).unwrap();
        assert_eq!(suppressed.bytes_suppressed, TS_PACKET_SIZE_WITH_RS);
        assert_eq!(suppressed.npd_bits, NPD_PACKET_SIZE_204_BIT | (1 << 6));
        assert_eq!(suppressed.payload.len(), TS_PACKET_SIZE_WITH_RS);

        let expanded = expand_null_packets(&suppressed.payload, suppressed.npd_bits).unwrap();
        assert_eq!(expanded, payload);
    }

    #[test]
    fn leaves_payload_unchanged_when_no_null_packets_are_present() {
        let payload = packet(0x1111, b"data", TS_PACKET_SIZE);
        let suppressed = suppress_null_packets(&payload).unwrap();
        assert_eq!(suppressed.bytes_suppressed, 0);
        assert_eq!(suppressed.payload, payload);
    }

    fn packet(pid: u16, label: &[u8], packet_size: usize) -> Vec<u8> {
        let mut packet = vec![0xff; packet_size];
        packet[0] = TS_SYNC_BYTE;
        packet[1..3].copy_from_slice(&pid.to_be_bytes());
        packet[3] = 0x10;
        packet[4..4 + label.len()].copy_from_slice(label);
        packet
    }
}
