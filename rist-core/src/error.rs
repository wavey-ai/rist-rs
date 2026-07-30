use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("packet too short: need at least {needed} bytes, got {actual}")]
    PacketTooShort { needed: usize, actual: usize },

    #[error("unsupported RTP version {0}")]
    UnsupportedRtpVersion(u8),

    #[error("unsupported RTP payload type {0}")]
    UnsupportedRtpPayloadType(u8),

    #[error("invalid RTCP length: header advertises {advertised} bytes, got {actual}")]
    InvalidRtcpLength { advertised: usize, actual: usize },

    #[error("NACK range exceeds the {maximum}-packet limit")]
    NackRangeTooLarge { maximum: usize },

    #[error("NACK packet exceeds the {maximum}-request limit")]
    NackPacketTooLarge { maximum: usize },

    #[error("invalid RIST URL: {0}")]
    InvalidUrl(String),

    #[error("RIST URL is missing a port")]
    MissingPort,

    #[error("RIST URL is missing a host")]
    MissingHost,

    #[error("invalid query value for {key}: {value}")]
    InvalidQueryValue { key: String, value: String },

    #[error("unsupported RIST URL query option: {0}")]
    UnsupportedQueryOption(String),

    #[error("RIST URL query option {option} requires {required}")]
    MissingQueryOption { option: String, required: String },

    #[error("unsupported AES key size {0}")]
    UnsupportedAesKeySize(u16),

    #[error("failed to generate PSK nonce")]
    RandomNonce,

    #[error("zero is not a valid transmitted PSK nonce")]
    InvalidPskNonce,

    #[error("PSK nonce changes exceeded the allowed derivation rate")]
    PskRekeyRateLimited,

    #[error("invalid recovery configuration: {0}")]
    InvalidRecoveryConfig(&'static str),

    #[error("unsupported GRE protocol type 0x{0:04x}")]
    UnsupportedGreProtocol(u16),

    #[error("invalid EAP packet")]
    InvalidEapPacket,

    #[error(
        "unexpected EAP message in {state}: code {code}, identifier {identifier}, subtype {subtype:?}"
    )]
    UnexpectedEapMessage {
        state: &'static str,
        code: u8,
        identifier: u8,
        subtype: Option<u8>,
    },

    #[error("EAP v4 passphrase authentication failed")]
    EapAuthenticationFailed,

    #[error("EAP v4 passphrase nonce was replayed")]
    EapReplay,

    #[error("invalid SRP group")]
    InvalidSrpGroup,

    #[error("unsupported SRP hash version {0}")]
    UnsupportedSrpHashVersion(u8),

    #[error("unsupported VSF subtype 0x{0:04x}")]
    UnsupportedVsfSubtype(u16),

    #[error("Main receiver flow capacity is {maximum}")]
    MainFlowCapacityExceeded { maximum: usize },

    #[error("invalid MPEG-TS packet group length {0}")]
    InvalidMpegTsLength(usize),

    #[error("invalid MPEG-TS sync byte 0x{0:02x}")]
    InvalidMpegTsSync(u8),
}
