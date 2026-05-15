use crate::{Error, Result};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub listen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryConfig {
    pub length_min: Duration,
    pub length_max: Duration,
    pub reorder_buffer: Duration,
    pub rtt_min: Duration,
    pub rtt_max: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            length_min: Duration::from_millis(1000),
            length_max: Duration::from_millis(1000),
            reorder_buffer: Duration::from_millis(15),
            rtt_min: Duration::from_millis(5),
            rtt_max: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionConfig {
    pub secret: String,
    pub key_size_bits: u16,
    pub key_rotation: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub endpoint: Endpoint,
    pub recovery: RecoveryConfig,
    pub encryption: Option<EncryptionConfig>,
    pub cname: Option<String>,
    pub srp_username: Option<String>,
    pub srp_password: Option<String>,
}

impl PeerConfig {
    pub fn parse(url: &str) -> Result<Self> {
        let parsed = parse_rist_url(url)?;
        let mut recovery = RecoveryConfig::default();
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
                "buffer-min" => recovery.length_min = parse_millis(key, value)?,
                "buffer-max" => recovery.length_max = parse_millis(key, value)?,
                "reorder-buffer" => recovery.reorder_buffer = parse_millis(key, value)?,
                "rtt-min" => recovery.rtt_min = parse_millis(key, value)?,
                "rtt-max" => recovery.rtt_max = parse_millis(key, value)?,
                "secret" => secret = Some(value.to_string()),
                "aes-type" => key_size_bits = Some(parse_aes_key_size(value)?),
                "key-rotation" => key_rotation = Some(parse_u32(key, value)?),
                "cname" => cname = Some(value.to_string()),
                "username" => srp_username = Some(value.to_string()),
                "password" => srp_password = Some(value.to_string()),
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
            },
            recovery,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_url() {
        let config = PeerConfig::parse("rist://@:5000").unwrap();
        assert_eq!(config.endpoint.host, "0.0.0.0");
        assert_eq!(config.endpoint.port, 5000);
        assert!(config.endpoint.listen);
    }

    #[test]
    fn parses_peer_url_with_recovery_and_crypto_options() {
        let config = PeerConfig::parse(
            "rist://127.0.0.1:6001?buffer=200&rtt-min=1&rtt-max=10&secret=s&aes-type=256&cname=test",
        )
        .unwrap();
        assert_eq!(config.endpoint.host, "127.0.0.1");
        assert!(!config.endpoint.listen);
        assert_eq!(config.recovery.length_min, Duration::from_millis(200));
        assert_eq!(config.recovery.rtt_max, Duration::from_millis(10));
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
}
