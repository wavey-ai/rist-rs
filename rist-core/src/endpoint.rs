use crate::main_profile::{DEFAULT_VIRT_DST_PORT, DEFAULT_VIRT_SRC_PORT};
use crate::{Error, Profile, Result};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub listen: bool,
    pub miface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryConfig {
    pub mode: RecoveryMode,
    pub max_bitrate: u32,
    pub return_max_bitrate: u32,
    pub length_min: Duration,
    pub length_max: Duration,
    pub reorder_buffer: Duration,
    pub rtt_min: Duration,
    pub rtt_max: Duration,
    pub min_retries: u32,
    pub max_retries: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            mode: RecoveryMode::Time,
            max_bitrate: 100_000,
            return_max_bitrate: 0,
            length_min: Duration::from_millis(1000),
            length_max: Duration::from_millis(1000),
            reorder_buffer: Duration::from_millis(15),
            rtt_min: Duration::from_millis(5),
            rtt_max: Duration::from_millis(500),
            min_retries: 6,
            max_retries: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    Disabled,
    Time,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionConfig {
    pub secret: String,
    pub key_size_bits: u16,
    pub key_rotation: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualPorts {
    pub src: u16,
    pub dst: u16,
}

impl Default for VirtualPorts {
    fn default() -> Self {
        Self {
            src: DEFAULT_VIRT_SRC_PORT,
            dst: DEFAULT_VIRT_DST_PORT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControlMode {
    Off,
    Normal,
    Aggressive,
}

impl Default for CongestionControlMode {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingMode {
    Source,
    Arrival,
    Rtc,
}

impl Default for TimingMode {
    fn default() -> Self {
        Self::Source
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub session_timeout: Duration,
    pub keepalive_interval: Duration,
    pub timing_mode: TimingMode,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_millis(2000),
            keepalive_interval: Duration::from_millis(1000),
            timing_mode: TimingMode::Source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedUrlConfig {
    pub profile: Option<Profile>,
    pub weight: u32,
    pub compression: Option<i32>,
    pub stream_id: Option<u16>,
    pub rtp_timestamp: Option<i32>,
    pub rtp_sequence: Option<i32>,
    pub rtp_output_payload_type: Option<u8>,
    pub multiplex_mode: Option<MultiplexMode>,
    pub multiplex_filter: Option<String>,
    pub verbose_level: Option<i32>,
}

impl Default for AdvancedUrlConfig {
    fn default() -> Self {
        Self {
            profile: None,
            weight: 0,
            compression: None,
            stream_id: None,
            rtp_timestamp: None,
            rtp_sequence: None,
            rtp_output_payload_type: None,
            multiplex_mode: None,
            multiplex_filter: None,
            verbose_level: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexMode {
    Auto,
    VirtualDestinationPort,
    VirtualSourcePort,
    Ipv4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub endpoint: Endpoint,
    pub virtual_ports: VirtualPorts,
    pub recovery: RecoveryConfig,
    pub congestion_control: CongestionControlMode,
    pub connection: ConnectionConfig,
    pub advanced: AdvancedUrlConfig,
    pub encryption: Option<EncryptionConfig>,
    pub cname: Option<String>,
    pub srp_username: Option<String>,
    pub srp_password: Option<String>,
}

impl PeerConfig {
    pub fn parse(url: &str) -> Result<Self> {
        let parsed = parse_rist_url(url)?;
        let mut miface = None;
        let mut virtual_ports = VirtualPorts::default();
        let mut recovery = RecoveryConfig::default();
        let mut congestion_control = CongestionControlMode::default();
        let mut connection = ConnectionConfig::default();
        let mut advanced = AdvancedUrlConfig::default();
        let mut secret = None;
        let mut key_size_bits = None;
        let mut key_rotation = None;
        let mut cname = None;
        let mut srp_username = None;
        let mut srp_password = None;

        for (key, value) in parse_query(parsed.query) {
            match key {
                "buffer" => {
                    let duration = parse_millis(key, value)?;
                    recovery.length_min = duration;
                    recovery.length_max = duration;
                }
                "bandwidth" => recovery.max_bitrate = parse_u32(key, value)?,
                "return-bandwidth" => recovery.return_max_bitrate = parse_u32(key, value)?,
                "buffer-min" => recovery.length_min = parse_millis(key, value)?,
                "buffer-max" => recovery.length_max = parse_millis(key, value)?,
                "reorder-buffer" => recovery.reorder_buffer = parse_millis(key, value)?,
                "rtt" => {
                    let duration = parse_millis(key, value)?;
                    recovery.rtt_min = duration;
                    recovery.rtt_max = duration;
                }
                "rtt-min" => recovery.rtt_min = parse_millis(key, value)?,
                "rtt-max" => recovery.rtt_max = parse_millis(key, value)?,
                "min-retries" => recovery.min_retries = parse_u32(key, value)?,
                "max-retries" => recovery.max_retries = parse_u32(key, value)?,
                "secret" => secret = Some(value.to_string()),
                "aes-type" => key_size_bits = Some(parse_aes_key_size(value)?),
                "key-rotation" => key_rotation = Some(parse_u32(key, value)?),
                "cname" => cname = Some(value.to_string()),
                "virt-src-port" => virtual_ports.src = parse_u16(key, value)?,
                "virt-dst-port" => virtual_ports.dst = parse_u16(key, value)?,
                "miface" => miface = non_empty_string(value),
                "weight" => advanced.weight = parse_u32(key, value)?,
                "compression" => advanced.compression = Some(parse_i32(key, value)?),
                "session-timeout" => connection.session_timeout = parse_millis(key, value)?,
                "keepalive-interval" => connection.keepalive_interval = parse_millis(key, value)?,
                "congestion-control" => congestion_control = parse_congestion_control(value)?,
                "timing-mode" => connection.timing_mode = parse_timing_mode(value)?,
                "username" => srp_username = Some(value.to_string()),
                "password" => srp_password = Some(value.to_string()),
                "stream-id" => advanced.stream_id = Some(parse_u16(key, value)?),
                "rtp-timestamp" => advanced.rtp_timestamp = Some(parse_i32(key, value)?),
                "rtp-sequence" => advanced.rtp_sequence = Some(parse_i32(key, value)?),
                "rtp-ptype" => advanced.rtp_output_payload_type = Some(parse_u8(key, value)?),
                "multiplex-mode" => advanced.multiplex_mode = Some(parse_multiplex_mode(value)?),
                "multiplex-filter" => advanced.multiplex_filter = non_empty_string(value),
                "profile" => advanced.profile = Some(parse_profile(value)?),
                "verbose-level" => advanced.verbose_level = Some(parse_i32(key, value)?),
                _ => {}
            }
        }

        let encryption = match (secret, key_size_bits) {
            (Some(secret), Some(key_size_bits)) => Some(EncryptionConfig {
                secret,
                key_size_bits,
                key_rotation,
            }),
            (Some(secret), None) => Some(EncryptionConfig {
                secret,
                key_size_bits: 128,
                key_rotation,
            }),
            (None, Some(key_size_bits)) => Some(EncryptionConfig {
                secret: String::new(),
                key_size_bits,
                key_rotation,
            }),
            (None, None) => None,
        };

        Ok(Self {
            endpoint: Endpoint {
                host: parsed.host,
                port: parsed.port,
                listen: parsed.listen,
                miface,
            },
            virtual_ports,
            recovery,
            congestion_control,
            connection,
            advanced,
            encryption,
            cname,
            srp_username,
            srp_password,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RistUrlParts<'a> {
    host: String,
    port: u16,
    listen: bool,
    query: &'a str,
}

fn parse_rist_url(input: &str) -> Result<RistUrlParts<'_>> {
    let Some(rest) = input.strip_prefix("rist://") else {
        return Err(Error::InvalidUrl("scheme must be rist".to_string()));
    };

    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    let listen = authority.starts_with('@');
    let authority = if listen { &authority[1..] } else { authority };
    let (host, port) = parse_authority(authority, listen)?;

    Ok(RistUrlParts {
        host,
        port,
        listen,
        query,
    })
}

fn parse_authority(authority: &str, listen: bool) -> Result<(String, u16)> {
    if authority.is_empty() {
        return Err(Error::MissingHost);
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, rest)) = rest.split_once(']') else {
            return Err(Error::InvalidUrl("unterminated IPv6 address".to_string()));
        };
        let Some(port) = rest.strip_prefix(':') else {
            return Err(Error::MissingPort);
        };
        (host, port)
    } else if let Some(port) = authority.strip_prefix(':') {
        if !listen {
            return Err(Error::MissingHost);
        }
        ("0.0.0.0", port)
    } else {
        authority.rsplit_once(':').ok_or(Error::MissingPort)?
    };

    if host.is_empty() {
        return Err(Error::MissingHost);
    }

    Ok((
        host.to_string(),
        port.parse().map_err(|_| Error::InvalidQueryValue {
            key: "port".to_string(),
            value: port.to_string(),
        })?,
    ))
}

fn parse_query(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').unwrap_or((part, "")))
}

fn parse_millis(key: &str, value: &str) -> Result<Duration> {
    Ok(Duration::from_millis(parse_u64(key, value)?))
}

fn parse_u32(key: &str, value: &str) -> Result<u32> {
    value.parse().map_err(|_| Error::InvalidQueryValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_i32(key: &str, value: &str) -> Result<i32> {
    value.parse().map_err(|_| Error::InvalidQueryValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_u16(key: &str, value: &str) -> Result<u16> {
    value.parse().map_err(|_| Error::InvalidQueryValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_u8(key: &str, value: &str) -> Result<u8> {
    value.parse().map_err(|_| Error::InvalidQueryValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_u64(key: &str, value: &str) -> Result<u64> {
    value.parse().map_err(|_| Error::InvalidQueryValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_aes_key_size(value: &str) -> Result<u16> {
    let value = value.parse().map_err(|_| Error::InvalidQueryValue {
        key: "aes-type".to_string(),
        value: value.to_string(),
    })?;
    match value {
        0 | 128 | 256 => Ok(value),
        other => Err(Error::UnsupportedAesKeySize(other)),
    }
}

fn parse_congestion_control(value: &str) -> Result<CongestionControlMode> {
    match value {
        "0" | "off" | "disabled" | "disable" => Ok(CongestionControlMode::Off),
        "1" | "normal" => Ok(CongestionControlMode::Normal),
        "2" | "aggressive" => Ok(CongestionControlMode::Aggressive),
        _ => Err(Error::InvalidQueryValue {
            key: "congestion-control".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_timing_mode(value: &str) -> Result<TimingMode> {
    match value {
        "0" | "source" => Ok(TimingMode::Source),
        "1" | "arrival" => Ok(TimingMode::Arrival),
        "2" | "rtc" => Ok(TimingMode::Rtc),
        _ => Err(Error::InvalidQueryValue {
            key: "timing-mode".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_multiplex_mode(value: &str) -> Result<MultiplexMode> {
    match value {
        "-1" | "auto" => Ok(MultiplexMode::Auto),
        "0" | "virt-dst-port" | "virtual-destination-port" => {
            Ok(MultiplexMode::VirtualDestinationPort)
        }
        "1" | "virt-src-port" | "virtual-source-port" => Ok(MultiplexMode::VirtualSourcePort),
        "2" | "ipv4" => Ok(MultiplexMode::Ipv4),
        _ => Err(Error::InvalidQueryValue {
            key: "multiplex-mode".to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_profile(value: &str) -> Result<Profile> {
    match value {
        "0" | "simple" => Ok(Profile::Simple),
        "1" | "main" => Ok(Profile::Main),
        "2" | "advanced" => Ok(Profile::Advanced),
        _ => Err(Error::InvalidQueryValue {
            key: "profile".to_string(),
            value: value.to_string(),
        }),
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_url() {
        let config = PeerConfig::parse("rist://@:5000").unwrap();
        assert_eq!(config.endpoint.host, "0.0.0.0");
        assert_eq!(config.endpoint.port, 5000);
        assert!(config.endpoint.listen);
        assert_eq!(config.endpoint.miface, None);
    }

    #[test]
    fn parses_peer_url_with_recovery_and_crypto_options() {
        let config = PeerConfig::parse(
            "rist://127.0.0.1:6001?buffer=200&rtt-min=1&rtt-max=10&secret=s&aes-type=256&cname=test&bandwidth=2000&return-bandwidth=300&min-retries=2&max-retries=8",
        )
        .unwrap();
        assert_eq!(config.endpoint.host, "127.0.0.1");
        assert!(!config.endpoint.listen);
        assert_eq!(config.recovery.length_min, Duration::from_millis(200));
        assert_eq!(config.recovery.rtt_max, Duration::from_millis(10));
        assert_eq!(config.recovery.max_bitrate, 2000);
        assert_eq!(config.recovery.return_max_bitrate, 300);
        assert_eq!(config.recovery.min_retries, 2);
        assert_eq!(config.recovery.max_retries, 8);
        assert_eq!(config.encryption.unwrap().key_size_bits, 256);
        assert_eq!(config.cname.as_deref(), Some("test"));
    }

    #[test]
    fn parses_bracketed_ipv6_url() {
        let config = PeerConfig::parse("rist://@[::1]:5000?rtt-min=1").unwrap();
        assert_eq!(config.endpoint.host, "::1");
        assert_eq!(config.endpoint.port, 5000);
        assert!(config.endpoint.listen);
    }

    #[test]
    fn parses_extended_librist_url_options() {
        let config = PeerConfig::parse(
            "rist://example.com:8000?virt-src-port=9000&virt-dst-port=9001&miface=en0&session-timeout=5000&keepalive-interval=700&congestion-control=aggressive&timing-mode=arrival&weight=4&compression=1&stream-id=3&rtp-timestamp=11&rtp-sequence=12&rtp-ptype=98&multiplex-mode=virt-src-port&multiplex-filter=abcd&profile=advanced&verbose-level=7&username=user&password=pass",
        )
        .unwrap();

        assert_eq!(config.virtual_ports.src, 9000);
        assert_eq!(config.virtual_ports.dst, 9001);
        assert_eq!(config.endpoint.miface.as_deref(), Some("en0"));
        assert_eq!(
            config.connection.session_timeout,
            Duration::from_millis(5000)
        );
        assert_eq!(
            config.connection.keepalive_interval,
            Duration::from_millis(700)
        );
        assert_eq!(config.connection.timing_mode, TimingMode::Arrival);
        assert_eq!(config.congestion_control, CongestionControlMode::Aggressive);
        assert_eq!(config.advanced.weight, 4);
        assert_eq!(config.advanced.compression, Some(1));
        assert_eq!(config.advanced.stream_id, Some(3));
        assert_eq!(config.advanced.rtp_timestamp, Some(11));
        assert_eq!(config.advanced.rtp_sequence, Some(12));
        assert_eq!(config.advanced.rtp_output_payload_type, Some(98));
        assert_eq!(
            config.advanced.multiplex_mode,
            Some(MultiplexMode::VirtualSourcePort)
        );
        assert_eq!(config.advanced.multiplex_filter.as_deref(), Some("abcd"));
        assert_eq!(config.advanced.profile, Some(Profile::Advanced));
        assert_eq!(config.advanced.verbose_level, Some(7));
        assert_eq!(config.srp_username.as_deref(), Some("user"));
        assert_eq!(config.srp_password.as_deref(), Some("pass"));
    }
}
