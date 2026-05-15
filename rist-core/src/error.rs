use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("packet too short: need at least {needed} bytes, got {actual}")]
    PacketTooShort { needed: usize, actual: usize },

    #[error("unsupported RTP version {0}")]
    UnsupportedRtpVersion(u8),

    #[error("invalid RTCP length: header advertises {advertised} bytes, got {actual}")]
    InvalidRtcpLength { advertised: usize, actual: usize },

    #[error("invalid RIST URL: {0}")]
    InvalidUrl(String),

    #[error("RIST URL is missing a port")]
    MissingPort,

    #[error("RIST URL is missing a host")]
    MissingHost,

    #[error("invalid query value for {key}: {value}")]
    InvalidQueryValue { key: String, value: String },

    #[error("unsupported AES key size {0}")]
    UnsupportedAesKeySize(u16),

    #[error("unsupported GRE protocol type 0x{0:04x}")]
    UnsupportedGreProtocol(u16),

    #[error("unsupported VSF subtype 0x{0:04x}")]
    UnsupportedVsfSubtype(u16),

    #[error("invalid MPEG-TS packet group length {0}")]
    InvalidMpegTsLength(usize),

    #[error("invalid MPEG-TS sync byte 0x{0:02x}")]
    InvalidMpegTsSync(u8),
}
