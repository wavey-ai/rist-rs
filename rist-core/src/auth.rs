use crate::{Error, Result};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub const EAPOL_VERSION_2: u8 = 2;
pub const EAPOL_VERSION_3: u8 = 3;
pub const EAPOL_VERSION_4: u8 = 4;
pub const EAPOL_TYPE_EAP_PACKET: u8 = 0;
pub const EAPOL_TYPE_START: u8 = 1;
pub const EAPOL_TYPE_LOGOFF: u8 = 2;

pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 4;
pub const EAP_TYPE_SRP_SHA1: u8 = 19;

pub const SRP_SHA256_DIGEST_LENGTH: usize = 32;
pub const SRP_DEFAULT_SALT_LEN: usize = 32;
const MAX_SRP_OPERATIONS_PER_SESSION: u8 = 8;
const MIN_SRP_MODULUS_BYTES: usize = 128;
const MAX_SRP_MODULUS_BYTES: usize = 1024;
const MAX_SRP_SALT_BYTES: usize = 64;
const EAP_V4_NONCE_LEN: usize = 12;
const EAP_V4_TAG_LEN: usize = 16;
const EAP_V4_MAX_PLAINTEXT: usize = 1400;

const SRP_2048_N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    Request,
    Response,
    Success,
    Failure,
}

impl EapCode {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Success),
            4 => Ok(Self::Failure),
            _ => Err(Error::InvalidEapPacket),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Success => 3,
            Self::Failure => 4,
        }
    }

    fn has_type(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub eap_type: Option<u8>,
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn request(identifier: u8, eap_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            code: EapCode::Request,
            identifier,
            eap_type: Some(eap_type),
            data: data.into(),
        }
    }

    pub fn response(identifier: u8, eap_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            code: EapCode::Response,
            identifier,
            eap_type: Some(eap_type),
            data: data.into(),
        }
    }

    pub fn success(identifier: u8) -> Self {
        Self {
            code: EapCode::Success,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    pub fn failure(identifier: u8) -> Self {
        Self {
            code: EapCode::Failure,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    pub fn identity_request(identifier: u8) -> Self {
        Self::request(identifier, EAP_TYPE_IDENTITY, Vec::new())
    }

    pub fn identity_response(identifier: u8, identity: impl AsRef<[u8]>) -> Self {
        Self::response(identifier, EAP_TYPE_IDENTITY, identity.as_ref().to_vec())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let type_len = usize::from(self.code.has_type());
        if self.code.has_type() && self.eap_type.is_none() {
            return Err(Error::InvalidEapPacket);
        }
        let len = 4 + type_len + self.data.len();
        let len_u16 = u16::try_from(len).map_err(|_| Error::InvalidEapPacket)?;
        let mut out = Vec::with_capacity(len);
        out.push(self.code.as_u8());
        out.push(self.identifier);
        out.extend_from_slice(&len_u16.to_be_bytes());
        if self.code.has_type() {
            out.push(self.eap_type.ok_or(Error::InvalidEapPacket)?);
        }
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(Error::PacketTooShort {
                needed: 4,
                actual: input.len(),
            });
        }
        let code = EapCode::from_u8(input[0])?;
        let identifier = input[1];
        let len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if len < 4 || len > input.len() {
            return Err(Error::InvalidEapPacket);
        }
        if code.has_type() {
            if len < 5 {
                return Err(Error::InvalidEapPacket);
            }
            Ok(Self {
                code,
                identifier,
                eap_type: Some(input[4]),
                data: input[5..len].to_vec(),
            })
        } else {
            Ok(Self {
                code,
                identifier,
                eap_type: None,
                data: input[4..len].to_vec(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolFrame {
    pub version: u8,
    pub packet_type: u8,
    pub payload: Vec<u8>,
}

impl EapolFrame {
    pub fn eap(version: u8, packet: &EapPacket) -> Result<Self> {
        Ok(Self {
            version,
            packet_type: EAPOL_TYPE_EAP_PACKET,
            payload: packet.encode()?,
        })
    }

    pub fn start(version: u8) -> Self {
        Self {
            version,
            packet_type: EAPOL_TYPE_START,
            payload: Vec::new(),
        }
    }

    pub fn logoff(version: u8) -> Self {
        Self {
            version,
            packet_type: EAPOL_TYPE_LOGOFF,
            payload: Vec::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = u16::try_from(self.payload.len()).map_err(|_| Error::InvalidEapPacket)?;
        let mut out = Vec::with_capacity(4 + self.payload.len());
        out.push(self.version);
        out.push(self.packet_type);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(Error::PacketTooShort {
                needed: 4,
                actual: input.len(),
            });
        }
        let len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if matches!(input[1], EAPOL_TYPE_START | EAPOL_TYPE_LOGOFF) && input.len() == 4 && len == 4
        {
            return Ok(Self {
                version: input[0],
                packet_type: input[1],
                payload: Vec::new(),
            });
        }
        if 4 + len > input.len() {
            return Err(Error::InvalidEapPacket);
        }
        Ok(Self {
            version: input[0],
            packet_type: input[1],
            payload: input[4..4 + len].to_vec(),
        })
    }

    pub fn eap_packet(&self) -> Result<EapPacket> {
        if self.packet_type != EAPOL_TYPE_EAP_PACKET {
            return Err(Error::InvalidEapPacket);
        }
        EapPacket::decode(&self.payload)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapSrpSubtype {
    Challenge,
    ServerKeyOrClientValidator,
    ServerValidator,
    LightweightRechallenge,
    PassphraseRequestResponse,
}

impl EapSrpSubtype {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Challenge),
            2 => Ok(Self::ServerKeyOrClientValidator),
            3 => Ok(Self::ServerValidator),
            4 => Ok(Self::LightweightRechallenge),
            0x10 => Ok(Self::PassphraseRequestResponse),
            _ => Err(Error::InvalidEapPacket),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Challenge => 1,
            Self::ServerKeyOrClientValidator => 2,
            Self::ServerValidator => 3,
            Self::LightweightRechallenge => 4,
            Self::PassphraseRequestResponse => 0x10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapSrpMessage {
    pub subtype: EapSrpSubtype,
    pub data: Vec<u8>,
}

impl EapSrpMessage {
    pub fn new(subtype: EapSrpSubtype, data: impl Into<Vec<u8>>) -> Self {
        Self {
            subtype,
            data: data.into(),
        }
    }

    pub fn into_eap_request(self, identifier: u8) -> EapPacket {
        EapPacket::request(identifier, EAP_TYPE_SRP_SHA1, self.encode_payload())
    }

    pub fn into_eap_response(self, identifier: u8) -> EapPacket {
        EapPacket::response(identifier, EAP_TYPE_SRP_SHA1, self.encode_payload())
    }

    pub fn from_eap_packet(packet: &EapPacket) -> Result<Self> {
        if packet.eap_type != Some(EAP_TYPE_SRP_SHA1) || packet.data.is_empty() {
            return Err(Error::InvalidEapPacket);
        }
        Ok(Self {
            subtype: EapSrpSubtype::from_u8(packet.data[0])?,
            data: packet.data[1..].to_vec(),
        })
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.subtype.as_u8());
        out.extend_from_slice(&self.data);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapSrpChallenge {
    pub server_name: Vec<u8>,
    pub salt: Vec<u8>,
    pub group: Option<SrpGroup>,
}

impl EapSrpChallenge {
    pub fn default_group(salt: impl Into<Vec<u8>>) -> Self {
        Self {
            server_name: Vec::new(),
            salt: salt.into(),
            group: None,
        }
    }

    pub fn encode_message(&self) -> Result<EapSrpMessage> {
        let mut out = Vec::new();
        write_tlv(&mut out, &self.server_name)?;
        write_tlv(&mut out, &self.salt)?;
        if let Some(group) = &self.group {
            write_tlv(&mut out, &group.generator_bytes())?;
            out.extend_from_slice(&group.modulus_bytes());
        } else {
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        Ok(EapSrpMessage::new(EapSrpSubtype::Challenge, out))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let server_name = read_tlv(input, &mut offset)?;
        let salt = read_tlv(input, &mut offset)?;
        let generator = read_tlv(input, &mut offset)?;
        let group = if generator.is_empty() {
            None
        } else {
            let modulus = input[offset..].to_vec();
            Some(SrpGroup::from_bytes(&modulus, &generator)?)
        };
        Ok(Self {
            server_name,
            salt,
            group,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SrpPassphrase {
    UseSessionKey,
    Passphrase(Vec<u8>),
}

impl fmt::Debug for SrpPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UseSessionKey => formatter.write_str("UseSessionKey"),
            Self::Passphrase(_) => formatter.write_str("Passphrase(<redacted>)"),
        }
    }
}

impl SrpPassphrase {
    pub fn encode_response(&self, identifier: u8, session_key: &[u8]) -> Result<EapSrpMessage> {
        let mut out = Vec::new();
        match self {
            Self::UseSessionKey => out.push(0x80),
            Self::Passphrase(passphrase) => {
                out.push(0x40);
                out.extend_from_slice(&aes_ctr_passphrase(
                    session_key,
                    256,
                    identifier,
                    passphrase,
                )?);
            }
        }
        Ok(EapSrpMessage::new(
            EapSrpSubtype::PassphraseRequestResponse,
            out,
        ))
    }

    pub fn decode_response(identifier: u8, session_key: &[u8], input: &[u8]) -> Result<Self> {
        let Some((&flags, encrypted)) = input.split_first() else {
            return Err(Error::InvalidEapPacket);
        };
        if flags & 0x80 != 0 {
            return Ok(Self::UseSessionKey);
        }
        let bits = if flags & 0x40 != 0 { 256 } else { 128 };
        Ok(Self::Passphrase(aes_ctr_passphrase(
            session_key,
            bits,
            identifier,
            encrypted,
        )?))
    }

    pub fn encode_response_v4(
        &self,
        identifier: u8,
        session_key: &[u8],
        client_to_server: bool,
        counter: u64,
    ) -> Result<EapSrpMessage> {
        let Self::Passphrase(passphrase) = self else {
            return Err(Error::InvalidEapPacket);
        };
        if passphrase.is_empty() || passphrase.len() > EAP_V4_MAX_PLAINTEXT {
            return Err(Error::InvalidEapPacket);
        }

        let flags = 0x40;
        let nonce = eap_v4_nonce(counter);
        let aad = eap_v4_aad(identifier, flags, &nonce);
        let key = eap_v4_direction_key(session_key, client_to_server)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::EapAuthenticationFailed)?;
        let mut ciphertext = passphrase.clone();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext)
            .map_err(|_| Error::EapAuthenticationFailed)?;

        let mut data = Vec::with_capacity(1 + EAP_V4_NONCE_LEN + ciphertext.len() + EAP_V4_TAG_LEN);
        data.push(flags);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        data.extend_from_slice(&tag);
        Ok(EapSrpMessage::new(
            EapSrpSubtype::PassphraseRequestResponse,
            data,
        ))
    }

    pub fn decode_response_v4(
        identifier: u8,
        session_key: &[u8],
        client_to_server: bool,
        input: &[u8],
        last_nonce: &mut Option<u64>,
    ) -> Result<Self> {
        if input.len() < 1 + EAP_V4_NONCE_LEN + EAP_V4_TAG_LEN || input[0] & 0x80 != 0 {
            return Err(Error::InvalidEapPacket);
        }
        let flags = input[0];
        let nonce: [u8; EAP_V4_NONCE_LEN] = input[1..1 + EAP_V4_NONCE_LEN]
            .try_into()
            .map_err(|_| Error::InvalidEapPacket)?;
        let ciphertext_end = input.len() - EAP_V4_TAG_LEN;
        let mut plaintext = input[1 + EAP_V4_NONCE_LEN..ciphertext_end].to_vec();
        if plaintext.is_empty() || plaintext.len() > EAP_V4_MAX_PLAINTEXT {
            return Err(Error::InvalidEapPacket);
        }
        let tag = Tag::from_slice(&input[ciphertext_end..]);
        let aad = eap_v4_aad(identifier, flags, &nonce);
        let key = eap_v4_direction_key(session_key, client_to_server)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::EapAuthenticationFailed)?;
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext, tag)
            .map_err(|_| Error::EapAuthenticationFailed)?;

        let counter =
            u64::from_be_bytes(nonce[4..].try_into().map_err(|_| Error::InvalidEapPacket)?);
        if last_nonce.is_some_and(|last| counter <= last) {
            plaintext.zeroize();
            return Err(Error::EapReplay);
        }
        *last_nonce = Some(counter);
        Ok(Self::Passphrase(plaintext))
    }
}

fn eap_v4_direction_key(
    session_key: &[u8],
    client_to_server: bool,
) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
    let hkdf = Hkdf::<Sha256>::from_prk(session_key).map_err(|_| Error::InvalidEapPacket)?;
    let label = if client_to_server {
        b"RIST-EAP-v4 pass c2s".as_slice()
    } else {
        b"RIST-EAP-v4 pass s2c".as_slice()
    };
    let mut output = [0; SRP_SHA256_DIGEST_LENGTH];
    hkdf.expand(label, &mut output)
        .map_err(|_| Error::InvalidEapPacket)?;
    Ok(output)
}

fn eap_v4_nonce(counter: u64) -> [u8; EAP_V4_NONCE_LEN] {
    let mut nonce = [0; EAP_V4_NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn eap_v4_aad(
    identifier: u8,
    flags: u8,
    nonce: &[u8; EAP_V4_NONCE_LEN],
) -> [u8; 5 + EAP_V4_NONCE_LEN] {
    let mut aad = [0; 5 + EAP_V4_NONCE_LEN];
    aad[..5].copy_from_slice(&[
        EapCode::Response.as_u8(),
        identifier,
        EAP_TYPE_SRP_SHA1,
        EapSrpSubtype::PassphraseRequestResponse.as_u8(),
        flags,
    ]);
    aad[5..].copy_from_slice(nonce);
    aad
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SrpHashVersion {
    LegacyMbedTlsSha256 = 0,
    CorrectSha256 = 1,
}

impl SrpHashVersion {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::LegacyMbedTlsSha256),
            1 => Ok(Self::CorrectSha256),
            _ => Err(Error::UnsupportedSrpHashVersion(value)),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    fn require_supported(self) -> Result<()> {
        match self {
            Self::CorrectSha256 => Ok(()),
            Self::LegacyMbedTlsSha256 => Err(Error::UnsupportedSrpHashVersion(self.as_u8())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpGroup {
    n: BigUint,
    g: BigUint,
    n_hex: String,
    g_hex: String,
}

impl SrpGroup {
    pub fn default_2048() -> Self {
        Self::from_hex(SRP_2048_N_HEX, "2").expect("static RFC 5054 SRP group is valid")
    }

    pub fn from_hex(n_hex: &str, g_hex: &str) -> Result<Self> {
        let n = parse_hex_biguint(n_hex)?;
        let g = parse_hex_biguint(g_hex)?;
        Self::new(n, g)
    }

    pub fn from_bytes(n: &[u8], g: &[u8]) -> Result<Self> {
        Self::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(g))
    }

    fn new(n: BigUint, g: BigUint) -> Result<Self> {
        let modulus_len = minimal_bytes(&n).len();
        if !(MIN_SRP_MODULUS_BYTES..=MAX_SRP_MODULUS_BYTES).contains(&modulus_len)
            || n.is_zero()
            || (&n & BigUint::from(1u8)).is_zero()
            || g <= BigUint::from(1u8)
            || g >= n
            || minimal_bytes(&g).len() > modulus_len
        {
            return Err(Error::InvalidSrpGroup);
        }
        Ok(Self {
            n_hex: biguint_hex(&n),
            g_hex: biguint_hex(&g),
            n,
            g,
        })
    }

    pub fn n_modulus_ascii(&self) -> &str {
        &self.n_hex
    }

    pub fn generator_ascii(&self) -> &str {
        &self.g_hex
    }

    pub fn modulus_bytes(&self) -> Vec<u8> {
        minimal_bytes(&self.n)
    }

    pub fn generator_bytes(&self) -> Vec<u8> {
        minimal_bytes(&self.g)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SrpUserRecord {
    pub username: String,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub generation: u64,
    pub hash_version: SrpHashVersion,
    pub group: SrpGroup,
    pub use_default_2048_bit_group: bool,
}

impl fmt::Debug for SrpUserRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SrpUserRecord")
            .field("username", &self.username)
            .field("salt", &"<redacted>")
            .field("verifier", &"<redacted>")
            .field("generation", &self.generation)
            .field("hash_version", &self.hash_version)
            .field("group", &self.group)
            .field(
                "use_default_2048_bit_group",
                &self.use_default_2048_bit_group,
            )
            .finish()
    }
}

impl SrpUserRecord {
    pub fn from_password(
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
        generation: u64,
    ) -> Result<Self> {
        let salt = random_salt()?;
        Self::from_password_with_salt(
            username,
            password,
            salt,
            generation,
            SrpHashVersion::CorrectSha256,
            SrpGroup::default_2048(),
            true,
        )
    }

    pub fn from_password_with_salt(
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
        generation: u64,
        hash_version: SrpHashVersion,
        group: SrpGroup,
        use_default_2048_bit_group: bool,
    ) -> Result<Self> {
        let username = username.into();
        let salt = canonical_srp_bytes(salt.as_ref());
        if salt.is_empty() || salt.len() > MAX_SRP_SALT_BYTES {
            return Err(Error::InvalidSrpGroup);
        }
        let verifier = srp_verifier(&group, &username, password.as_ref(), &salt, hash_version)?;
        Ok(Self {
            username,
            salt,
            verifier,
            generation,
            hash_version,
            group,
            use_default_2048_bit_group,
        })
    }

    pub fn verify_password(&self, password: impl AsRef<[u8]>) -> Result<bool> {
        let verifier = srp_verifier(
            &self.group,
            &self.username,
            password.as_ref(),
            &self.salt,
            self.hash_version,
        )?;
        Ok(verifier == self.verifier)
    }
}

impl Drop for SrpUserRecord {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.verifier.zeroize();
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SrpCredentialStore {
    records: BTreeMap<String, Vec<SrpUserRecord>>,
}

impl SrpCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, record: SrpUserRecord) {
        let records = self.records.entry(record.username.clone()).or_default();
        if let Some(existing) = records.iter_mut().find(|existing| {
            existing.generation == record.generation && existing.hash_version == record.hash_version
        }) {
            *existing = record;
        } else {
            records.push(record);
            records.sort_by_key(|record| (record.generation, record.hash_version));
        }
    }

    pub fn upsert_password_with_salt(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
        generation: u64,
        hash_version: SrpHashVersion,
    ) -> Result<SrpUserRecord> {
        let record = SrpUserRecord::from_password_with_salt(
            username,
            password,
            salt,
            generation,
            hash_version,
            SrpGroup::default_2048(),
            true,
        )?;
        self.upsert(record.clone());
        Ok(record)
    }

    pub fn stage_password(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> Result<SrpUserRecord> {
        let username = username.into();
        let generation = self
            .current(&username)
            .map(|record| record.generation.saturating_add(1))
            .unwrap_or(1);
        let record = SrpUserRecord::from_password(username, password, generation)?;
        self.upsert(record.clone());
        Ok(record)
    }

    pub fn current(&self, username: &str) -> Option<&SrpUserRecord> {
        self.best_record(username, SrpHashVersion::CorrectSha256)
    }

    pub fn lookup(
        &self,
        username: &str,
        max_hash_version: SrpHashVersion,
    ) -> Option<&SrpUserRecord> {
        self.best_record(username, max_hash_version)
    }

    pub fn lookup_changed(
        &self,
        username: &str,
        max_hash_version: SrpHashVersion,
        cached_generation: u64,
    ) -> Option<&SrpUserRecord> {
        self.lookup(username, max_hash_version)
            .filter(|record| record.generation != cached_generation)
    }

    pub fn verify(&self, username: &str, password: impl AsRef<[u8]>) -> Result<bool> {
        let Some(record) = self.current(username) else {
            return Ok(false);
        };
        record.verify_password(password)
    }

    pub fn retire_before(&mut self, username: &str, generation: u64) {
        if let Some(records) = self.records.get_mut(username) {
            records.retain(|record| record.generation >= generation);
        }
    }

    fn best_record(
        &self,
        username: &str,
        max_hash_version: SrpHashVersion,
    ) -> Option<&SrpUserRecord> {
        self.records.get(username).and_then(|records| {
            records
                .iter()
                .filter(|record| record.hash_version <= max_hash_version)
                .max_by_key(|record| (record.generation, record.hash_version))
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PassphraseRollover {
    current: Vec<u8>,
    pending: Option<Vec<u8>>,
    generation: u64,
}

impl fmt::Debug for PassphraseRollover {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassphraseRollover")
            .field("current", &"<redacted>")
            .field("pending", &self.pending.as_ref().map(|_| "<redacted>"))
            .field("generation", &self.generation)
            .finish()
    }
}

impl PassphraseRollover {
    pub fn new(current: impl Into<Vec<u8>>) -> Self {
        Self {
            current: current.into(),
            pending: None,
            generation: 1,
        }
    }

    pub fn current(&self) -> &[u8] {
        &self.current
    }

    pub fn pending(&self) -> Option<&[u8]> {
        self.pending.as_deref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn stage(&mut self, passphrase: impl Into<Vec<u8>>) -> u64 {
        self.pending = Some(passphrase.into());
        self.generation = self.generation.saturating_add(1);
        self.generation
    }

    pub fn activate_pending(&mut self) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        self.current = pending;
        true
    }

    pub fn discard_pending(&mut self) {
        self.pending = None;
    }
}

impl Drop for PassphraseRollover {
    fn drop(&mut self) {
        self.current.zeroize();
        if let Some(pending) = &mut self.pending {
            pending.zeroize();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientAuthState {
    Idle,
    AwaitingIdentity,
    AwaitingChallenge,
    AwaitingServerKey,
    AwaitingServerValidator,
    Authenticated,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EapSrpClientSession {
    username: String,
    password: Vec<u8>,
    eap_version: u8,
    srp: Option<SrpClient>,
    state: ClientAuthState,
    use_session_key_as_passphrase: bool,
    tx_passphrase: Option<Vec<u8>>,
    rx_passphrase: Option<Vec<u8>>,
    srp_compat_legacy: bool,
    expensive_operations: u8,
    last_request: Option<(EapPacket, EapolFrame)>,
    peer_eap_version: u8,
    tx_nonce_counter: u64,
}

impl EapSrpClientSession {
    pub fn new(username: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        Self {
            username: username.into(),
            password: password.as_ref().to_vec(),
            eap_version: EAPOL_VERSION_4,
            srp: None,
            state: ClientAuthState::Idle,
            use_session_key_as_passphrase: true,
            tx_passphrase: None,
            rx_passphrase: None,
            srp_compat_legacy: false,
            expensive_operations: 0,
            last_request: None,
            peer_eap_version: 0,
            tx_nonce_counter: 0,
        }
    }

    pub fn with_eap_version(mut self, version: u8) -> Self {
        self.eap_version = version;
        self
    }

    pub fn with_tx_passphrase(mut self, passphrase: impl AsRef<[u8]>) -> Self {
        self.use_session_key_as_passphrase = false;
        self.tx_passphrase = Some(passphrase.as_ref().to_vec());
        self
    }

    pub fn with_session_key_passphrase(mut self, enabled: bool) -> Self {
        self.use_session_key_as_passphrase = enabled;
        self
    }

    /// Use the pre-v0.2.16 unpadded SRP transcript.
    pub fn with_srp_compat_legacy(mut self, enabled: bool) -> Self {
        self.srp_compat_legacy = enabled;
        self
    }

    pub fn start(&mut self) -> EapolFrame {
        self.clear_exchange();
        self.state = ClientAuthState::AwaitingIdentity;
        EapolFrame::start(self.eap_version)
    }

    pub fn authenticated(&self) -> bool {
        self.state == ClientAuthState::Authenticated
    }

    pub fn set_password(&mut self, password: impl AsRef<[u8]>) {
        self.password = password.as_ref().to_vec();
        self.clear_exchange();
    }

    pub fn session_key(&self) -> Option<&[u8; SRP_SHA256_DIGEST_LENGTH]> {
        self.srp.as_ref().and_then(SrpClient::session_key)
    }

    pub fn rx_passphrase(&self) -> Option<&[u8]> {
        self.rx_passphrase.as_deref()
    }

    pub fn handle_frame(&mut self, frame: &EapolFrame) -> Result<Option<EapolFrame>> {
        self.peer_eap_version = self.peer_eap_version.max(frame.version);
        match frame.packet_type {
            EAPOL_TYPE_LOGOFF | EAPOL_TYPE_START => {
                self.clear_exchange();
                return Ok(None);
            }
            EAPOL_TYPE_EAP_PACKET => {}
            _ => return Ok(None),
        }
        let packet = frame.eap_packet()?;
        match packet.code {
            EapCode::Request => {
                if let Some((cached_request, cached_response)) = &self.last_request {
                    if cached_request == &packet {
                        return Ok(Some(cached_response.clone()));
                    }
                }
                let response = self.handle_request(frame.version, &packet)?;
                if let Some(response) = &response {
                    self.last_request = Some((packet, response.clone()));
                }
                Ok(response)
            }
            EapCode::Success => Err(Error::InvalidEapPacket),
            EapCode::Failure => {
                self.clear_exchange();
                Err(Error::InvalidEapPacket)
            }
            EapCode::Response => Err(Error::InvalidEapPacket),
        }
    }

    fn handle_request(&mut self, version: u8, packet: &EapPacket) -> Result<Option<EapolFrame>> {
        match packet.eap_type {
            Some(EAP_TYPE_IDENTITY) => {
                self.clear_exchange();
                let response =
                    EapPacket::identity_response(packet.identifier, self.username.as_bytes());
                self.state = ClientAuthState::AwaitingChallenge;
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            Some(EAP_TYPE_SRP_SHA1) => {
                let message = EapSrpMessage::from_eap_packet(packet)?;
                self.handle_srp_request(version, packet.identifier, message)
            }
            _ => Err(Error::UnexpectedEapMessage {
                state: "client request state",
                code: packet.code.as_u8(),
                identifier: packet.identifier,
                subtype: packet.data.first().copied(),
            }),
        }
    }

    fn handle_srp_request(
        &mut self,
        version: u8,
        identifier: u8,
        message: EapSrpMessage,
    ) -> Result<Option<EapolFrame>> {
        match message.subtype {
            EapSrpSubtype::Challenge if self.state == ClientAuthState::AwaitingChallenge => {
                self.consume_expensive_operation()?;
                let challenge = EapSrpChallenge::decode(&message.data)?;
                let group = challenge.group.unwrap_or_else(SrpGroup::default_2048);
                let hash_version = if version >= EAPOL_VERSION_3 {
                    SrpHashVersion::CorrectSha256
                } else {
                    SrpHashVersion::LegacyMbedTlsSha256
                };
                let srp = SrpClient::new_with_compat(
                    group,
                    challenge.salt,
                    hash_version,
                    self.srp_compat_legacy,
                )?;
                let response = EapSrpMessage::new(EapSrpSubtype::Challenge, srp.public_key())
                    .into_eap_response(identifier);
                self.srp = Some(srp);
                self.state = ClientAuthState::AwaitingServerKey;
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            EapSrpSubtype::ServerKeyOrClientValidator
                if self.state == ClientAuthState::AwaitingServerKey =>
            {
                self.consume_expensive_operation()?;
                let Some(srp) = &mut self.srp else {
                    return Err(Error::InvalidEapPacket);
                };
                let m1 = srp.handle_server_key(&message.data, &self.username, &self.password)?;
                let mut data = vec![0; 4];
                if self.use_session_key_as_passphrase {
                    data[3] |= 1;
                }
                data.extend_from_slice(&m1);
                let response = EapSrpMessage::new(EapSrpSubtype::ServerKeyOrClientValidator, data)
                    .into_eap_response(identifier);
                self.state = ClientAuthState::AwaitingServerValidator;
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            EapSrpSubtype::ServerValidator
                if self.state == ClientAuthState::AwaitingServerValidator =>
            {
                if message.data.len() < 4 + SRP_SHA256_DIGEST_LENGTH {
                    return Err(Error::InvalidEapPacket);
                }
                let Some(srp) = &mut self.srp else {
                    return Err(Error::InvalidEapPacket);
                };
                if !srp.verify_server(&message.data[4..4 + SRP_SHA256_DIGEST_LENGTH])? {
                    self.clear_exchange();
                    return Err(Error::InvalidEapPacket);
                }
                if message.data[3] & 1 != 0 {
                    self.rx_passphrase = srp.session_key().map(|key| key.to_vec());
                }
                self.state = ClientAuthState::Authenticated;
                self.expensive_operations = 0;
                let response = EapPacket::success(identifier);
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            EapSrpSubtype::PassphraseRequestResponse => {
                if self.state != ClientAuthState::Authenticated {
                    return Err(Error::InvalidEapPacket);
                }
                let Some(key) = self.session_key().copied() else {
                    return Err(Error::InvalidEapPacket);
                };
                let passphrase = if self.use_session_key_as_passphrase {
                    SrpPassphrase::UseSessionKey
                } else {
                    SrpPassphrase::Passphrase(self.tx_passphrase.clone().unwrap_or_default())
                };
                let response = if self.eap_version >= EAPOL_VERSION_4
                    && self.peer_eap_version >= EAPOL_VERSION_4
                {
                    let response = passphrase.encode_response_v4(
                        identifier,
                        &key,
                        true,
                        self.tx_nonce_counter,
                    )?;
                    self.tx_nonce_counter = self.tx_nonce_counter.wrapping_add(1);
                    response
                } else {
                    passphrase.encode_response(identifier, &key)?
                }
                .into_eap_response(identifier);
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            subtype => Err(Error::UnexpectedEapMessage {
                state: "client SRP state",
                code: EapCode::Request.as_u8(),
                identifier,
                subtype: Some(subtype.as_u8()),
            }),
        }
    }

    fn consume_expensive_operation(&mut self) -> Result<()> {
        if self.expensive_operations >= MAX_SRP_OPERATIONS_PER_SESSION {
            self.clear_exchange();
            return Err(Error::InvalidEapPacket);
        }
        self.expensive_operations += 1;
        Ok(())
    }

    fn clear_exchange(&mut self) {
        self.srp = None;
        self.state = ClientAuthState::Idle;
        if let Some(passphrase) = &mut self.rx_passphrase {
            passphrase.zeroize();
        }
        self.rx_passphrase = None;
        self.last_request = None;
        self.tx_nonce_counter = 0;
    }
}

impl Drop for EapSrpClientSession {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(passphrase) = &mut self.tx_passphrase {
            passphrase.zeroize();
        }
        if let Some(passphrase) = &mut self.rx_passphrase {
            passphrase.zeroize();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatorAuthState {
    Idle,
    AwaitingIdentity(u8),
    AwaitingClientKey(u8),
    AwaitingClientProof(u8),
    AwaitingClientAck(u8),
    Authenticated,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EapSrpAuthenticatorSession {
    store: SrpCredentialStore,
    eap_version: u8,
    next_identifier: u8,
    username: Option<String>,
    srp: Option<SrpAuthenticator>,
    state: AuthenticatorAuthState,
    use_session_key_as_passphrase: bool,
    rx_passphrase: Option<Vec<u8>>,
    srp_compat_legacy: bool,
    identifier_ready: bool,
    expensive_operations: u8,
    last_response: Option<(EapPacket, EapolFrame)>,
    peer_eap_version: u8,
    rx_last_nonce: Option<u64>,
}

impl EapSrpAuthenticatorSession {
    pub fn new(store: SrpCredentialStore) -> Self {
        let mut identifier = [0u8; 1];
        let identifier_ready = getrandom::getrandom(&mut identifier).is_ok();
        Self {
            store,
            eap_version: EAPOL_VERSION_4,
            next_identifier: identifier[0],
            username: None,
            srp: None,
            state: AuthenticatorAuthState::Idle,
            use_session_key_as_passphrase: true,
            rx_passphrase: None,
            srp_compat_legacy: false,
            identifier_ready,
            expensive_operations: 0,
            last_response: None,
            peer_eap_version: 0,
            rx_last_nonce: None,
        }
    }

    pub fn with_eap_version(mut self, version: u8) -> Self {
        self.eap_version = version;
        self
    }

    pub fn with_initial_identifier(mut self, identifier: u8) -> Self {
        self.next_identifier = identifier;
        self.identifier_ready = true;
        self
    }

    pub fn with_explicit_passphrase(mut self) -> Self {
        self.use_session_key_as_passphrase = false;
        self
    }

    pub fn with_session_key_passphrase(mut self, enabled: bool) -> Self {
        self.use_session_key_as_passphrase = enabled;
        self
    }

    /// Use the pre-v0.2.16 unpadded SRP transcript.
    pub fn with_srp_compat_legacy(mut self, enabled: bool) -> Self {
        self.srp_compat_legacy = enabled;
        self
    }

    pub fn authenticated(&self) -> bool {
        self.state == AuthenticatorAuthState::Authenticated
    }

    pub fn authenticated_username(&self) -> Option<&str> {
        if self.authenticated() {
            self.username.as_deref()
        } else {
            None
        }
    }

    pub fn stage_password(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> Result<SrpUserRecord> {
        self.store.stage_password(username, password)
    }

    pub fn retire_generations_before(&mut self, username: &str, generation: u64) {
        self.store.retire_before(username, generation);
    }

    pub fn current_generation(&self, username: &str) -> Option<u64> {
        self.store.current(username).map(|record| record.generation)
    }

    pub fn session_key(&self) -> Option<&[u8; SRP_SHA256_DIGEST_LENGTH]> {
        self.srp.as_ref().and_then(SrpAuthenticator::session_key)
    }

    pub fn rx_passphrase(&self) -> Option<&[u8]> {
        self.rx_passphrase.as_deref()
    }

    pub fn request_identity(&mut self) -> Result<EapolFrame> {
        self.clear_exchange();
        let identifier = self.next_identifier()?;
        self.state = AuthenticatorAuthState::AwaitingIdentity(identifier);
        EapolFrame::eap(self.eap_version, &EapPacket::identity_request(identifier))
    }

    pub fn handle_frame(&mut self, frame: &EapolFrame) -> Result<Option<EapolFrame>> {
        self.peer_eap_version = self.peer_eap_version.max(frame.version);
        match frame.packet_type {
            EAPOL_TYPE_START => Ok(Some(self.request_identity()?)),
            EAPOL_TYPE_LOGOFF => {
                self.clear_exchange();
                Ok(None)
            }
            EAPOL_TYPE_EAP_PACKET => {
                let packet = frame.eap_packet()?;
                match packet.code {
                    EapCode::Response => {
                        if let Some((cached_response, cached_request)) = &self.last_response {
                            if cached_response == &packet {
                                return Ok(Some(cached_request.clone()));
                            }
                        }
                        let request = self.handle_response(frame.version, &packet)?;
                        if let Some(request) = &request {
                            self.last_response = Some((packet, request.clone()));
                        }
                        Ok(request)
                    }
                    EapCode::Success => match self.state {
                        AuthenticatorAuthState::AwaitingClientAck(identifier)
                            if identifier == packet.identifier
                                && self
                                    .srp
                                    .as_ref()
                                    .and_then(SrpAuthenticator::session_key)
                                    .is_some() =>
                        {
                            self.state = AuthenticatorAuthState::Authenticated;
                            self.expensive_operations = 0;
                            Ok(None)
                        }
                        _ => Err(Error::InvalidEapPacket),
                    },
                    EapCode::Failure => {
                        self.clear_exchange();
                        Err(Error::InvalidEapPacket)
                    }
                    EapCode::Request => Err(Error::InvalidEapPacket),
                }
            }
            _ => Ok(None),
        }
    }

    fn handle_response(&mut self, version: u8, packet: &EapPacket) -> Result<Option<EapolFrame>> {
        match packet.eap_type {
            Some(EAP_TYPE_IDENTITY)
                if self.state == AuthenticatorAuthState::AwaitingIdentity(packet.identifier) =>
            {
                self.handle_identity_response(version, packet)
            }
            Some(EAP_TYPE_SRP_SHA1) => {
                let message = EapSrpMessage::from_eap_packet(packet)?;
                self.handle_srp_response(version, packet.identifier, message)
            }
            _ => Err(Error::InvalidEapPacket),
        }
    }

    fn handle_identity_response(
        &mut self,
        version: u8,
        packet: &EapPacket,
    ) -> Result<Option<EapolFrame>> {
        self.consume_expensive_operation()?;
        let username =
            String::from_utf8(packet.data.clone()).map_err(|_| Error::InvalidEapPacket)?;
        let max_hash_version = if version >= EAPOL_VERSION_3 {
            SrpHashVersion::CorrectSha256
        } else {
            SrpHashVersion::LegacyMbedTlsSha256
        };
        let record = self
            .store
            .lookup(&username, max_hash_version)
            .ok_or(Error::InvalidEapPacket)?
            .clone();
        let challenge = EapSrpChallenge {
            server_name: Vec::new(),
            salt: record.salt.clone(),
            group: (!record.use_default_2048_bit_group).then(|| record.group.clone()),
        }
        .encode_message()?;
        self.username = Some(username);
        self.srp = Some(SrpAuthenticator::new_with_compat(
            record,
            self.srp_compat_legacy,
        )?);
        let identifier = self.next_identifier()?;
        let request = challenge.into_eap_request(identifier);
        self.state = AuthenticatorAuthState::AwaitingClientKey(identifier);
        Ok(Some(EapolFrame::eap(self.eap_version, &request)?))
    }

    fn handle_srp_response(
        &mut self,
        version: u8,
        identifier: u8,
        message: EapSrpMessage,
    ) -> Result<Option<EapolFrame>> {
        match message.subtype {
            EapSrpSubtype::Challenge
                if self.state == AuthenticatorAuthState::AwaitingClientKey(identifier) =>
            {
                self.consume_expensive_operation()?;
                let Some(srp) = &mut self.srp else {
                    return Err(Error::InvalidEapPacket);
                };
                let server_key = srp.handle_client_key(&message.data)?;
                let request_identifier = self.next_identifier()?;
                let request =
                    EapSrpMessage::new(EapSrpSubtype::ServerKeyOrClientValidator, server_key)
                        .into_eap_request(request_identifier);
                self.state = AuthenticatorAuthState::AwaitingClientProof(request_identifier);
                Ok(Some(EapolFrame::eap(self.eap_version, &request)?))
            }
            EapSrpSubtype::ServerKeyOrClientValidator
                if self.state == AuthenticatorAuthState::AwaitingClientProof(identifier) =>
            {
                self.consume_expensive_operation()?;
                if message.data.len() < 4 + SRP_SHA256_DIGEST_LENGTH {
                    return Err(Error::InvalidEapPacket);
                }
                let Some(srp) = &mut self.srp else {
                    return Err(Error::InvalidEapPacket);
                };
                let m2 = srp.verify_client(&message.data[4..4 + SRP_SHA256_DIGEST_LENGTH])?;
                if message.data[3] & 1 != 0 {
                    self.rx_passphrase = srp.session_key().map(|key| key.to_vec());
                }
                let mut data = vec![0; 4];
                if self.use_session_key_as_passphrase {
                    data[3] |= 1;
                }
                data.extend_from_slice(&m2);
                let request_identifier = self.next_identifier()?;
                let request = EapSrpMessage::new(EapSrpSubtype::ServerValidator, data)
                    .into_eap_request(request_identifier);
                self.state = AuthenticatorAuthState::AwaitingClientAck(request_identifier);
                Ok(Some(EapolFrame::eap(self.eap_version, &request)?))
            }
            EapSrpSubtype::PassphraseRequestResponse
                if self.state == AuthenticatorAuthState::Authenticated =>
            {
                let Some(key) = self.session_key().copied() else {
                    return Err(Error::InvalidEapPacket);
                };
                self.rx_passphrase = Some(
                    match if self.eap_version >= EAPOL_VERSION_4
                        && self.peer_eap_version >= EAPOL_VERSION_4
                    {
                        if version < EAPOL_VERSION_4 {
                            return Err(Error::InvalidEapPacket);
                        }
                        SrpPassphrase::decode_response_v4(
                            identifier,
                            &key,
                            true,
                            &message.data,
                            &mut self.rx_last_nonce,
                        )?
                    } else {
                        SrpPassphrase::decode_response(identifier, &key, &message.data)?
                    } {
                        SrpPassphrase::UseSessionKey => key.to_vec(),
                        SrpPassphrase::Passphrase(passphrase) => passphrase,
                    },
                );
                let response = EapPacket::success(identifier);
                Ok(Some(EapolFrame::eap(self.eap_version, &response)?))
            }
            _ => Err(Error::InvalidEapPacket),
        }
    }

    fn next_identifier(&mut self) -> Result<u8> {
        if !self.identifier_ready {
            return Err(Error::RandomNonce);
        }
        let identifier = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        Ok(identifier)
    }

    fn consume_expensive_operation(&mut self) -> Result<()> {
        if self.expensive_operations >= MAX_SRP_OPERATIONS_PER_SESSION {
            self.clear_exchange();
            return Err(Error::InvalidEapPacket);
        }
        self.expensive_operations += 1;
        Ok(())
    }

    fn clear_exchange(&mut self) {
        self.username = None;
        self.srp = None;
        self.state = AuthenticatorAuthState::Idle;
        if let Some(passphrase) = &mut self.rx_passphrase {
            passphrase.zeroize();
        }
        self.rx_passphrase = None;
        self.last_response = None;
        self.rx_last_nonce = None;
    }
}

impl Drop for EapSrpAuthenticatorSession {
    fn drop(&mut self) {
        if let Some(passphrase) = &mut self.rx_passphrase {
            passphrase.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SrpClient {
    group: SrpGroup,
    salt: Vec<u8>,
    hash_version: SrpHashVersion,
    a: BigUint,
    a_pub: BigUint,
    b_pub: Option<BigUint>,
    key: Option<[u8; SRP_SHA256_DIGEST_LENGTH]>,
    m1: Option<[u8; SRP_SHA256_DIGEST_LENGTH]>,
    legacy_pad: bool,
}

impl SrpClient {
    pub fn new(
        group: SrpGroup,
        salt: impl AsRef<[u8]>,
        hash_version: SrpHashVersion,
    ) -> Result<Self> {
        Self::new_with_compat(group, salt, hash_version, false)
    }

    pub fn new_with_compat(
        group: SrpGroup,
        salt: impl AsRef<[u8]>,
        hash_version: SrpHashVersion,
        legacy_pad: bool,
    ) -> Result<Self> {
        let a = random_nonzero_below(&group.n)?;
        Self::with_private_ephemeral_and_compat(group, salt, hash_version, a, legacy_pad)
    }

    pub fn with_private_ephemeral(
        group: SrpGroup,
        salt: impl AsRef<[u8]>,
        hash_version: SrpHashVersion,
        a: BigUint,
    ) -> Result<Self> {
        Self::with_private_ephemeral_and_compat(group, salt, hash_version, a, false)
    }

    pub fn with_private_ephemeral_and_compat(
        group: SrpGroup,
        salt: impl AsRef<[u8]>,
        hash_version: SrpHashVersion,
        a: BigUint,
        legacy_pad: bool,
    ) -> Result<Self> {
        hash_version.require_supported()?;
        let salt = canonical_srp_bytes(salt.as_ref());
        if a.is_zero() || salt.is_empty() || salt.len() > MAX_SRP_SALT_BYTES {
            return Err(Error::InvalidSrpGroup);
        }
        let a_pub = group.g.modpow(&a, &group.n);
        Ok(Self {
            group,
            salt,
            hash_version,
            a,
            a_pub,
            b_pub: None,
            key: None,
            m1: None,
            legacy_pad,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        minimal_bytes(&self.a_pub)
    }

    pub fn handle_server_key(
        &mut self,
        server_key: impl AsRef<[u8]>,
        username: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
        let b_pub = BigUint::from_bytes_be(server_key.as_ref());
        if b_pub.is_zero() || &b_pub % &self.group.n == BigUint::zero() {
            return Err(Error::InvalidSrpGroup);
        }
        let u = srp_scrambler(&self.group, &self.a_pub, &b_pub, self.legacy_pad)?;
        if &u % &self.group.n == BigUint::zero() {
            return Err(Error::InvalidSrpGroup);
        }
        let k = srp_multiplier(&self.group, self.legacy_pad)?;
        let x = srp_private_key(username, password.as_ref(), &self.salt, self.hash_version)?;
        let gx = self.group.g.modpow(&x, &self.group.n);
        let kgx = (k * gx) % &self.group.n;
        let base = if b_pub >= kgx {
            (&b_pub - &kgx) % &self.group.n
        } else {
            (&b_pub + &self.group.n - &kgx) % &self.group.n
        };
        let exponent = &self.a + (&u * &x);
        let shared = base.modpow(&exponent, &self.group.n);
        let key = srp_session_key(&shared);
        let m1 = srp_client_proof(
            &self.group,
            username,
            &self.salt,
            &self.a_pub,
            &b_pub,
            &key,
            self.hash_version,
        )?;
        self.b_pub = Some(b_pub);
        self.key = Some(key);
        self.m1 = Some(m1);
        Ok(m1)
    }

    pub fn verify_server(&self, server_proof: &[u8]) -> Result<bool> {
        let Some(key) = self.key else {
            return Err(Error::InvalidEapPacket);
        };
        let Some(m1) = self.m1 else {
            return Err(Error::InvalidEapPacket);
        };
        let expected = srp_server_proof(&self.a_pub, &m1, &key, self.hash_version)?;
        Ok(bool::from(expected.as_slice().ct_eq(server_proof)))
    }

    pub fn session_key(&self) -> Option<&[u8; SRP_SHA256_DIGEST_LENGTH]> {
        self.key.as_ref()
    }
}

impl Drop for SrpClient {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.a = BigUint::zero();
        self.a_pub = BigUint::zero();
        self.b_pub = None;
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        if let Some(proof) = &mut self.m1 {
            proof.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SrpAuthenticator {
    record: SrpUserRecord,
    a_pub: Option<BigUint>,
    b: BigUint,
    b_pub: Option<BigUint>,
    key: Option<[u8; SRP_SHA256_DIGEST_LENGTH]>,
    m2: Option<[u8; SRP_SHA256_DIGEST_LENGTH]>,
    legacy_pad: bool,
}

impl SrpAuthenticator {
    pub fn new(record: SrpUserRecord) -> Result<Self> {
        Self::new_with_compat(record, false)
    }

    pub fn new_with_compat(record: SrpUserRecord, legacy_pad: bool) -> Result<Self> {
        let b = random_nonzero_below(&record.group.n)?;
        Self::with_private_ephemeral_and_compat(record, b, legacy_pad)
    }

    pub fn with_private_ephemeral(record: SrpUserRecord, b: BigUint) -> Result<Self> {
        Self::with_private_ephemeral_and_compat(record, b, false)
    }

    pub fn with_private_ephemeral_and_compat(
        record: SrpUserRecord,
        b: BigUint,
        legacy_pad: bool,
    ) -> Result<Self> {
        record.hash_version.require_supported()?;
        if b.is_zero() {
            return Err(Error::InvalidSrpGroup);
        }
        Ok(Self {
            record,
            a_pub: None,
            b,
            b_pub: None,
            key: None,
            m2: None,
            legacy_pad,
        })
    }

    pub fn handle_client_key(&mut self, client_key: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let a_pub = BigUint::from_bytes_be(client_key.as_ref());
        if a_pub.is_zero() || &a_pub % &self.record.group.n == BigUint::zero() {
            return Err(Error::InvalidSrpGroup);
        }
        let k = srp_multiplier(&self.record.group, self.legacy_pad)?;
        let verifier = BigUint::from_bytes_be(&self.record.verifier);
        let gb = self.record.group.g.modpow(&self.b, &self.record.group.n);
        let b_pub = ((k * verifier) + gb) % &self.record.group.n;
        let out = minimal_bytes(&b_pub);
        self.a_pub = Some(a_pub);
        self.b_pub = Some(b_pub);
        Ok(out)
    }

    pub fn verify_client(&mut self, client_proof: &[u8]) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
        let Some(a_pub) = &self.a_pub else {
            return Err(Error::InvalidEapPacket);
        };
        let Some(b_pub) = &self.b_pub else {
            return Err(Error::InvalidEapPacket);
        };
        let verifier = BigUint::from_bytes_be(&self.record.verifier);
        let u = srp_scrambler(&self.record.group, a_pub, b_pub, self.legacy_pad)?;
        let vu = verifier.modpow(&u, &self.record.group.n);
        let avu = (a_pub * vu) % &self.record.group.n;
        let shared = avu.modpow(&self.b, &self.record.group.n);
        let key = srp_session_key(&shared);
        let expected_m1 = srp_client_proof(
            &self.record.group,
            &self.record.username,
            &self.record.salt,
            a_pub,
            b_pub,
            &key,
            self.record.hash_version,
        )?;
        if !bool::from(expected_m1.as_slice().ct_eq(client_proof)) {
            return Err(Error::InvalidEapPacket);
        }
        let m2 = srp_server_proof(a_pub, &expected_m1, &key, self.record.hash_version)?;
        self.key = Some(key);
        self.m2 = Some(m2);
        Ok(m2)
    }

    pub fn session_key(&self) -> Option<&[u8; SRP_SHA256_DIGEST_LENGTH]> {
        self.key.as_ref()
    }
}

impl Drop for SrpAuthenticator {
    fn drop(&mut self) {
        self.a_pub = None;
        self.b = BigUint::zero();
        self.b_pub = None;
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        if let Some(proof) = &mut self.m2 {
            proof.zeroize();
        }
    }
}

pub fn srp_private_key(
    username: &str,
    password: &[u8],
    salt: &[u8],
    hash_version: SrpHashVersion,
) -> Result<BigUint> {
    hash_version.require_supported()?;
    let mut inner = Sha256::new();
    inner.update(username.as_bytes());
    inner.update(b":");
    inner.update(password);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(canonical_srp_bytes(salt));
    outer.update(inner);
    Ok(BigUint::from_bytes_be(&outer.finalize()))
}

pub fn srp_verifier(
    group: &SrpGroup,
    username: &str,
    password: &[u8],
    salt: &[u8],
    hash_version: SrpHashVersion,
) -> Result<Vec<u8>> {
    let x = srp_private_key(username, password, salt, hash_version)?;
    Ok(minimal_bytes(&group.g.modpow(&x, &group.n)))
}

fn srp_multiplier(group: &SrpGroup, legacy_pad: bool) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(&srp_hash_pair(
        group, &group.n, &group.g, legacy_pad,
    )?))
}

fn srp_scrambler(
    group: &SrpGroup,
    a_pub: &BigUint,
    b_pub: &BigUint,
    legacy_pad: bool,
) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(&srp_hash_pair(
        group, a_pub, b_pub, legacy_pad,
    )?))
}

fn srp_hash_pair(
    group: &SrpGroup,
    left: &BigUint,
    right: &BigUint,
    legacy_pad: bool,
) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
    if legacy_pad {
        return Ok(sha256_join(&[minimal_bytes(left), minimal_bytes(right)]));
    }
    let width = group.modulus_bytes().len();
    Ok(sha256_join(&[
        padded_srp_bytes(left, width)?,
        padded_srp_bytes(right, width)?,
    ]))
}

fn padded_srp_bytes(value: &BigUint, width: usize) -> Result<Vec<u8>> {
    let bytes = minimal_bytes(value);
    if bytes.len() > width {
        return Err(Error::InvalidSrpGroup);
    }
    let mut padded = vec![0; width];
    padded[width - bytes.len()..].copy_from_slice(&bytes);
    Ok(padded)
}

fn srp_session_key(shared: &BigUint) -> [u8; SRP_SHA256_DIGEST_LENGTH] {
    sha256_join(&[minimal_bytes(shared)])
}

fn srp_client_proof(
    group: &SrpGroup,
    username: &str,
    salt: &[u8],
    a_pub: &BigUint,
    b_pub: &BigUint,
    key: &[u8; SRP_SHA256_DIGEST_LENGTH],
    hash_version: SrpHashVersion,
) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
    hash_version.require_supported()?;
    let hash_n = sha256_join(&[group.modulus_bytes()]);
    let hash_g = sha256_join(&[group.generator_bytes()]);
    let mut xor = [0; SRP_SHA256_DIGEST_LENGTH];
    for (out, (n, g)) in xor.iter_mut().zip(hash_n.into_iter().zip(hash_g)) {
        *out = n ^ g;
    }
    Ok(sha256_join(&[
        xor.to_vec(),
        sha256_join(&[username.as_bytes().to_vec()]).to_vec(),
        canonical_srp_bytes(salt),
        minimal_bytes(a_pub),
        minimal_bytes(b_pub),
        key.to_vec(),
    ]))
}

fn srp_server_proof(
    a_pub: &BigUint,
    m1: &[u8; SRP_SHA256_DIGEST_LENGTH],
    key: &[u8; SRP_SHA256_DIGEST_LENGTH],
    hash_version: SrpHashVersion,
) -> Result<[u8; SRP_SHA256_DIGEST_LENGTH]> {
    hash_version.require_supported()?;
    Ok(sha256_join(&[
        minimal_bytes(a_pub),
        m1.to_vec(),
        key.to_vec(),
    ]))
}

fn aes_ctr_passphrase(
    session_key: &[u8],
    key_size_bits: u16,
    identifier: u8,
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut iv = [0; 16];
    iv[15] = identifier;
    let mut out = input.to_vec();
    match key_size_bits {
        128 => {
            if session_key.len() < 16 {
                return Err(Error::UnsupportedAesKeySize(128));
            }
            let mut cipher = Aes128Ctr::new((&session_key[..16]).into(), &iv.into());
            cipher.apply_keystream(&mut out);
        }
        256 => {
            if session_key.len() < 32 {
                return Err(Error::UnsupportedAesKeySize(256));
            }
            let mut cipher = Aes256Ctr::new((&session_key[..32]).into(), &iv.into());
            cipher.apply_keystream(&mut out);
        }
        other => return Err(Error::UnsupportedAesKeySize(other)),
    }
    Ok(out)
}

fn write_tlv(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| Error::InvalidEapPacket)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn read_tlv(input: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset + 2 > input.len() {
        return Err(Error::InvalidEapPacket);
    }
    let len = usize::from(u16::from_be_bytes([input[*offset], input[*offset + 1]]));
    *offset += 2;
    if *offset + len > input.len() {
        return Err(Error::InvalidEapPacket);
    }
    let value = input[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

fn random_salt() -> Result<Vec<u8>> {
    let mut salt = [0; SRP_DEFAULT_SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| Error::RandomNonce)?;
    let salt = canonical_srp_bytes(&salt);
    if salt.is_empty() {
        return random_salt();
    }
    Ok(salt)
}

fn random_nonzero_below(max: &BigUint) -> Result<BigUint> {
    let len = minimal_bytes(max).len();
    loop {
        let mut bytes = vec![0; len];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::RandomNonce)?;
        let value = BigUint::from_bytes_be(&bytes);
        if !value.is_zero() && &value < max {
            return Ok(value);
        }
    }
}

fn parse_hex_biguint(input: &str) -> Result<BigUint> {
    BigUint::parse_bytes(input.as_bytes(), 16)
        .filter(|value| !value.is_zero())
        .ok_or(Error::InvalidSrpGroup)
}

fn biguint_hex(value: &BigUint) -> String {
    let mut out = String::new();
    for byte in minimal_bytes(value) {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn minimal_bytes(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

fn canonical_srp_bytes(input: &[u8]) -> Vec<u8> {
    minimal_bytes(&BigUint::from_bytes_be(input))
}

fn sha256_join(parts: &[Vec<u8>]) -> [u8; SRP_SHA256_DIGEST_LENGTH] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRP_TEST_N_512: &str = concat!(
        "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B",
        "1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3"
    );
    const SAMPLE_SALT: &str = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
    const SAMPLE_VERIFIER: &str = concat!(
        "2E06FEA163D6E9FF0FA7ED6C59233389D0DBA0C08C0F72F6DAD1E2A3D8B92A77",
        "2F070439D1C11B87FA990D2DAF04EB830CC77D61ACC4B253297379CD8E6DC3AF"
    );
    const CLIENT_A: &str = concat!(
        "92C4CEFB95A1AE2E576A252B19273FD4613F44FDA4AC8CC84A089D5740756223",
        "943882BAD34CB55F35139CDDB60E0D19ACD2B884CFB27F53C8EA969269ABE014"
    );
    const SERVER_B: &str = concat!(
        "858CDC811B5EEAA7F58C12767D309EBD2DF1D46F59EF5686052E6511CF853CA4",
        "E66910BDBD28CBEAE2F2DEE7F6BF3756757BD69E88D48C77B5371A82EF52AD84"
    );
    const CLIENT_M1: &str = "E28147C801BAB9C37647C1FF4A29FA720E3F5676434FB85EA9A752CC1F9B1AD4";
    const SERVER_M2: &str = "84F19797916FBDCAB1321CA78B575B145B586150248AFAA156361B8BCB139B32";

    #[test]
    fn eapol_identity_packet_round_trips() {
        let packet = EapPacket::identity_response(7, b"rist");
        let frame = EapolFrame::eap(EAPOL_VERSION_2, &packet).unwrap();
        let encoded = frame.encode().unwrap();
        assert_eq!(
            encoded,
            vec![
                2,
                0,
                0,
                9,
                2,
                7,
                0,
                9,
                EAP_TYPE_IDENTITY,
                b'r',
                b'i',
                b's',
                b't'
            ]
        );
        let decoded = EapolFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.eap_packet().unwrap(), packet);
    }

    #[test]
    fn srp_challenge_uses_librist_default_group_shape() {
        let challenge = EapSrpChallenge::default_group(hex(SAMPLE_SALT));
        let message = challenge.encode_message().unwrap();
        assert_eq!(message.subtype, EapSrpSubtype::Challenge);
        let decoded = EapSrpChallenge::decode(&message.data).unwrap();
        assert_eq!(decoded.salt, hex(SAMPLE_SALT));
        assert!(decoded.group.is_none());
    }

    #[test]
    fn eapol_accepts_librist_start_length_quirk() {
        let frame = EapolFrame::decode(&[EAPOL_VERSION_3, EAPOL_TYPE_START, 0, 4]).unwrap();
        assert_eq!(frame.packet_type, EAPOL_TYPE_START);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn srp_verifier_matches_librist_correct_hashing_vector() {
        let group = legacy_test_group();
        let verifier = srp_verifier(
            &group,
            "rist",
            b"mainprofile",
            &hex(SAMPLE_SALT),
            SrpHashVersion::CorrectSha256,
        )
        .unwrap();
        assert_eq!(upper_hex(&verifier), SAMPLE_VERIFIER);
    }

    #[test]
    fn legacy_srp_exchange_matches_pre_v0216_librist_vector() {
        let group = legacy_test_group();
        let record = SrpUserRecord::from_password_with_salt(
            "rist",
            b"mainprofile",
            hex(SAMPLE_SALT),
            1,
            SrpHashVersion::CorrectSha256,
            group.clone(),
            false,
        )
        .unwrap();
        let a =
            parse_hex_biguint("138AB4045633AD14961CB1AD0720B1989104151C0708794491113302CCCC27D5")
                .unwrap();
        let b =
            parse_hex_biguint("ED0D58FF861A1FC75A0829BEA5F1392D2B13AB2B05CBCD6ED1E71AAAD761E856")
                .unwrap();
        let mut client = SrpClient::with_private_ephemeral_and_compat(
            group,
            hex(SAMPLE_SALT),
            SrpHashVersion::CorrectSha256,
            a,
            true,
        )
        .unwrap();
        assert_eq!(upper_hex(&client.public_key()), CLIENT_A);

        let mut auth =
            SrpAuthenticator::with_private_ephemeral_and_compat(record, b, true).unwrap();
        let server_key = auth.handle_client_key(client.public_key()).unwrap();
        assert_eq!(upper_hex(&server_key), SERVER_B);

        let client_m1 = client
            .handle_server_key(&server_key, "rist", b"mainprofile")
            .unwrap();
        assert_eq!(upper_hex(&client_m1), CLIENT_M1);

        let server_m2 = auth.verify_client(&client_m1).unwrap();
        assert_eq!(upper_hex(&server_m2), SERVER_M2);
        assert!(client.verify_server(&server_m2).unwrap());
        assert_eq!(client.session_key(), auth.session_key());
    }

    #[test]
    fn eap_srp_sessions_authenticate_over_frames() {
        let record = SrpUserRecord::from_password_with_salt(
            "rist",
            b"mainprofile",
            hex(SAMPLE_SALT),
            1,
            SrpHashVersion::CorrectSha256,
            SrpGroup::default_2048(),
            true,
        )
        .unwrap();
        let mut store = SrpCredentialStore::new();
        store.upsert(record);
        let mut authenticator = EapSrpAuthenticatorSession::new(store).with_initial_identifier(41);
        let mut client = EapSrpClientSession::new("rist", b"mainprofile");

        let identity_request = authenticator
            .handle_frame(&client.start())
            .unwrap()
            .unwrap();
        let identity_response = client.handle_frame(&identity_request).unwrap().unwrap();
        let challenge = authenticator
            .handle_frame(&identity_response)
            .unwrap()
            .unwrap();
        let client_key = client.handle_frame(&challenge).unwrap().unwrap();
        let server_key = authenticator.handle_frame(&client_key).unwrap().unwrap();
        let client_validator = client.handle_frame(&server_key).unwrap().unwrap();
        let server_validator = authenticator
            .handle_frame(&client_validator)
            .unwrap()
            .unwrap();
        let success = client.handle_frame(&server_validator).unwrap().unwrap();
        authenticator.handle_frame(&success).unwrap();

        assert!(client.authenticated());
        assert!(authenticator.authenticated());
        assert_eq!(client.session_key(), authenticator.session_key());
        assert_eq!(
            client.rx_passphrase(),
            client.session_key().map(|key| key.as_slice())
        );
        assert_eq!(
            authenticator.rx_passphrase(),
            authenticator.session_key().map(|key| key.as_slice())
        );
    }

    #[test]
    fn credential_store_returns_changed_generations() {
        let mut store = SrpCredentialStore::new();
        let first = store
            .upsert_password_with_salt(
                "rist",
                b"first",
                hex(SAMPLE_SALT),
                1,
                SrpHashVersion::CorrectSha256,
            )
            .unwrap();
        assert_eq!(
            store.lookup_changed("rist", SrpHashVersion::CorrectSha256, 1),
            None
        );
        let second = store.stage_password("rist", b"second").unwrap();
        assert_eq!(second.generation, first.generation + 1);
        assert_eq!(
            store
                .lookup_changed("rist", SrpHashVersion::CorrectSha256, 1)
                .unwrap()
                .generation,
            2
        );
        assert!(store.verify("rist", b"second").unwrap());
        assert!(!store.verify("rist", b"first").unwrap());
    }

    #[test]
    fn passphrase_response_encrypts_with_srp_session_key() {
        let key = [0x11; SRP_SHA256_DIGEST_LENGTH];
        let message = SrpPassphrase::Passphrase(b"next-secret".to_vec())
            .encode_response(44, &key)
            .unwrap();
        assert_ne!(&message.data[1..], b"next-secret");
        let decoded = SrpPassphrase::decode_response(44, &key, &message.data).unwrap();
        assert_eq!(decoded, SrpPassphrase::Passphrase(b"next-secret".to_vec()));
    }

    #[test]
    fn eap_v4_passphrases_are_directional_authenticated_and_replay_safe() {
        let key = [0x42; SRP_SHA256_DIGEST_LENGTH];
        let passphrase = SrpPassphrase::Passphrase(b"next-secret".to_vec());
        let message = passphrase.encode_response_v4(44, &key, true, 7).unwrap();
        assert_eq!(message.data[0], 0x40);
        assert!(!message.data.windows(11).any(|part| part == b"next-secret"));

        let mut last_nonce = None;
        let decoded =
            SrpPassphrase::decode_response_v4(44, &key, true, &message.data, &mut last_nonce)
                .unwrap();
        assert_eq!(decoded, passphrase);
        assert_eq!(last_nonce, Some(7));
        assert_eq!(
            SrpPassphrase::decode_response_v4(44, &key, true, &message.data, &mut last_nonce)
                .unwrap_err(),
            Error::EapReplay
        );

        let mut tampered = message.data.clone();
        tampered[1 + EAP_V4_NONCE_LEN] ^= 1;
        assert_eq!(
            SrpPassphrase::decode_response_v4(44, &key, true, &tampered, &mut None).unwrap_err(),
            Error::EapAuthenticationFailed
        );
        assert_eq!(
            SrpPassphrase::decode_response_v4(44, &key, false, &message.data, &mut None)
                .unwrap_err(),
            Error::EapAuthenticationFailed
        );
    }

    #[test]
    fn authentication_requires_the_proof_state_and_matching_identifier() {
        let mut client = EapSrpClientSession::new("rist", b"secret");
        client.start();
        let unsolicited_success = EapolFrame::eap(EAPOL_VERSION_4, &EapPacket::success(9)).unwrap();
        assert_eq!(
            client.handle_frame(&unsolicited_success).unwrap_err(),
            Error::InvalidEapPacket
        );
        assert!(!client.authenticated());

        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"secret").unwrap();
        let mut authenticator = EapSrpAuthenticatorSession::new(store).with_initial_identifier(20);
        let identity = authenticator.request_identity().unwrap();
        let request = identity.eap_packet().unwrap();
        let wrong_identifier =
            EapPacket::identity_response(request.identifier.wrapping_add(1), b"rist");
        let frame = EapolFrame::eap(EAPOL_VERSION_4, &wrong_identifier).unwrap();
        assert!(authenticator.handle_frame(&frame).is_err());
        assert!(!authenticator.authenticated());
    }

    #[test]
    fn rejects_network_srp_groups_below_the_supported_strength() {
        assert_eq!(
            SrpGroup::from_hex(SRP_TEST_N_512, "2").unwrap_err(),
            Error::InvalidSrpGroup
        );
    }

    fn legacy_test_group() -> SrpGroup {
        let n = parse_hex_biguint(SRP_TEST_N_512).unwrap();
        let g = BigUint::from(2u8);
        SrpGroup {
            n_hex: biguint_hex(&n),
            g_hex: biguint_hex(&g),
            n,
            g,
        }
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    fn upper_hex(input: &[u8]) -> String {
        let mut out = String::new();
        for byte in input {
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }
}
