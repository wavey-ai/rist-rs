use crate::{Error, Result};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const PBKDF2_HMAC_SHA256_ITERATIONS: u32 = 1024;
pub const AES_BLOCK_SIZE: usize = 16;
pub const DEFAULT_KEY_ROTATION_PACKETS: u64 = 1_000_000;
const MAX_RECEIVE_REKEYS_PER_SECOND: u8 = 8;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes192Ctr = ctr::Ctr128BE<Aes192>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    pub fn from_bits(bits: u32) -> Result<Self> {
        match bits {
            128 => Ok(Self::Aes128),
            192 => Ok(Self::Aes192),
            256 => Ok(Self::Aes256),
            other => Err(Error::UnsupportedAesKeySize(other as u16)),
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
        }
    }

    fn bytes(self) -> usize {
        (self.bits() / 8) as usize
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PskKey {
    key_size: AesKeySize,
    password: Zeroizing<Vec<u8>>,
    nonce: [u8; 4],
    key_rotation: u64,
    used_times: u64,
    aes_key: Zeroizing<Vec<u8>>,
    previous_nonce: Option<[u8; 4]>,
    previous_aes_key: Option<Zeroizing<Vec<u8>>>,
    rekey_window_start: Instant,
    rekeys_in_window: u8,
}

impl PskKey {
    pub fn new(key_size_bits: u32, password: impl AsRef<[u8]>) -> Result<Self> {
        Self::with_key_rotation(key_size_bits, DEFAULT_KEY_ROTATION_PACKETS, password)
    }

    pub fn with_key_rotation(
        key_size_bits: u32,
        key_rotation: u64,
        password: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let mut nonce = [0; 4];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::RandomNonce)?;
        Self::from_nonce(key_size_bits, key_rotation, password, nonce)
    }

    pub fn receiver(key_size_bits: u32, password: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_nonce_inner(key_size_bits, 0, password, [0; 4], true)
    }

    pub fn from_nonce(
        key_size_bits: u32,
        key_rotation: u64,
        password: impl AsRef<[u8]>,
        nonce: [u8; 4],
    ) -> Result<Self> {
        Self::from_nonce_inner(key_size_bits, key_rotation, password, nonce, false)
    }

    fn from_nonce_inner(
        key_size_bits: u32,
        key_rotation: u64,
        password: impl AsRef<[u8]>,
        nonce: [u8; 4],
        allow_unset_nonce: bool,
    ) -> Result<Self> {
        if nonce == [0; 4] && !allow_unset_nonce {
            return Err(Error::InvalidPskNonce);
        }
        let key_size = AesKeySize::from_bits(key_size_bits)?;
        let password = Zeroizing::new(password.as_ref().to_vec());
        let aes_key = Zeroizing::new(derive_aes_key(key_size, &password, &nonce));
        Ok(Self {
            key_size,
            password,
            nonce,
            key_rotation,
            used_times: 0,
            aes_key,
            previous_nonce: None,
            previous_aes_key: None,
            rekey_window_start: Instant::now(),
            rekeys_in_window: 0,
        })
    }

    pub fn key_size(&self) -> AesKeySize {
        self.key_size
    }

    pub fn nonce(&self) -> [u8; 4] {
        self.nonce
    }

    pub fn set_nonce(&mut self, nonce: [u8; 4]) -> Result<()> {
        if nonce == [0; 4] {
            return Err(Error::InvalidPskNonce);
        }
        if self.nonce != nonce {
            let now = Instant::now();
            if now.duration_since(self.rekey_window_start) >= Duration::from_secs(1) {
                self.rekey_window_start = now;
                self.rekeys_in_window = 0;
            }
            if self.rekeys_in_window >= MAX_RECEIVE_REKEYS_PER_SECOND {
                return Err(Error::PskRekeyRateLimited);
            }
            self.rekeys_in_window += 1;
            self.previous_nonce = (self.nonce != [0; 4]).then_some(self.nonce);
            self.previous_aes_key = self
                .previous_nonce
                .map(|_| Zeroizing::new(self.aes_key.to_vec()));
            self.nonce = nonce;
            self.aes_key =
                Zeroizing::new(derive_aes_key(self.key_size, &self.password, &self.nonce));
            self.used_times = 0;
        }
        Ok(())
    }

    pub fn encrypt(&mut self, gre_version: u8, sequence: u32, input: &[u8]) -> Vec<u8> {
        self.crypt(gre_version, sequence, input)
    }

    pub fn decrypt(
        &mut self,
        nonce: [u8; 4],
        gre_version: u8,
        sequence: u32,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        if self.previous_nonce == Some(nonce) {
            let key = self
                .previous_aes_key
                .as_ref()
                .ok_or(Error::InvalidPskNonce)?;
            return Ok(crypt_with_key(
                self.key_size,
                key,
                gre_version,
                sequence,
                input,
            ));
        }
        self.set_nonce(nonce)?;
        Ok(self.crypt(gre_version, sequence, input))
    }

    fn crypt(&mut self, gre_version: u8, sequence: u32, input: &[u8]) -> Vec<u8> {
        if self.key_rotation > 0 && self.used_times >= self.key_rotation {
            self.advance_nonce();
            self.aes_key =
                Zeroizing::new(derive_aes_key(self.key_size, &self.password, &self.nonce));
            self.used_times = 0;
        }

        let out = crypt_with_key(self.key_size, &self.aes_key, gre_version, sequence, input);
        self.used_times += 1;
        out
    }

    fn advance_nonce(&mut self) {
        let current = self.nonce;
        let mut next = [0; 4];
        for _ in 0..8 {
            if getrandom::getrandom(&mut next).is_ok() && next != [0; 4] && next != current {
                self.nonce = next;
                return;
            }
        }
        // Retaining the existing random nonce is safer than switching to a
        // predictable nonce when the operating-system CSPRNG is unavailable.
    }
}

impl fmt::Debug for PskKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PskKey")
            .field("key_size", &self.key_size)
            .field("nonce", &self.nonce)
            .field("key_rotation", &self.key_rotation)
            .field("used_times", &self.used_times)
            .field("password", &"<redacted>")
            .field("aes_key", &"<redacted>")
            .finish()
    }
}

fn crypt_with_key(
    key_size: AesKeySize,
    aes_key: &[u8],
    gre_version: u8,
    sequence: u32,
    input: &[u8],
) -> Vec<u8> {
    let mut out = input.to_vec();
    let iv = iv_for_sequence(gre_version, sequence);
    match key_size {
        AesKeySize::Aes128 => {
            let mut cipher = Aes128Ctr::new(aes_key.into(), &iv.into());
            cipher.apply_keystream(&mut out);
        }
        AesKeySize::Aes192 => {
            let mut cipher = Aes192Ctr::new(aes_key.into(), &iv.into());
            cipher.apply_keystream(&mut out);
        }
        AesKeySize::Aes256 => {
            let mut cipher = Aes256Ctr::new(aes_key.into(), &iv.into());
            cipher.apply_keystream(&mut out);
        }
    }
    out
}

pub fn derive_aes_key(key_size: AesKeySize, password: &[u8], nonce: &[u8; 4]) -> Vec<u8> {
    let mut key = vec![0; key_size.bytes()];
    pbkdf2_hmac::<Sha256>(password, nonce, PBKDF2_HMAC_SHA256_ITERATIONS, &mut key);
    key
}

pub fn iv_for_sequence(gre_version: u8, sequence: u32) -> [u8; AES_BLOCK_SIZE] {
    let mut iv = [0; AES_BLOCK_SIZE];
    let offset = if gre_version >= 1 { 0 } else { 12 };
    iv[offset..offset + 4].copy_from_slice(&sequence.to_be_bytes());
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_distinct_keys_per_nonce() {
        let key_a = derive_aes_key(AesKeySize::Aes128, b"secret", &[1, 2, 3, 4]);
        let key_b = derive_aes_key(AesKeySize::Aes128, b"secret", &[4, 3, 2, 1]);
        assert_eq!(key_a.len(), 16);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn aes_ctr_round_trips_payload() {
        let mut tx = PskKey::from_nonce(256, 0, b"secret", [1, 2, 3, 4]).unwrap();
        let mut rx = PskKey::receiver(256, b"secret").unwrap();
        let encrypted = tx.encrypt(2, 42, b"payload");
        assert_ne!(encrypted, b"payload");
        let decrypted = rx.decrypt([1, 2, 3, 4], 2, 42, &encrypted).unwrap();
        assert_eq!(decrypted, b"payload");
    }

    #[test]
    fn tx_key_rotates_nonce_after_configured_uses() {
        let mut tx = PskKey::from_nonce(256, 2, b"secret", [1, 2, 3, 4]).unwrap();
        assert_eq!(tx.nonce(), [1, 2, 3, 4]);
        tx.encrypt(2, 0, b"first");
        assert_eq!(tx.nonce(), [1, 2, 3, 4]);
        tx.encrypt(2, 1, b"second");
        assert_eq!(tx.nonce(), [1, 2, 3, 4]);
        tx.encrypt(2, 2, b"third");
        assert_ne!(tx.nonce(), [1, 2, 3, 4]);
        assert_ne!(tx.nonce(), [0; 4]);
    }

    #[test]
    fn rejects_zero_and_rate_limits_untrusted_nonce_changes() {
        assert_eq!(
            PskKey::from_nonce(128, 0, b"secret", [0; 4]).unwrap_err(),
            Error::InvalidPskNonce
        );

        let mut rx = PskKey::receiver(128, b"secret").unwrap();
        for nonce in 1..=MAX_RECEIVE_REKEYS_PER_SECOND {
            rx.set_nonce([0, 0, 0, nonce]).unwrap();
        }
        assert_eq!(
            rx.set_nonce([0, 0, 0, MAX_RECEIVE_REKEYS_PER_SECOND + 1])
                .unwrap_err(),
            Error::PskRekeyRateLimited
        );
    }

    #[test]
    fn iv_places_sequence_like_librist() {
        let gre_v2 = iv_for_sequence(2, 0x0102_0304);
        assert_eq!(&gre_v2[..4], &[1, 2, 3, 4]);
        assert_eq!(&gre_v2[4..], &[0; 12]);

        let gre_v0 = iv_for_sequence(0, 0x0102_0304);
        assert_eq!(&gre_v0[..12], &[0; 12]);
        assert_eq!(&gre_v0[12..], &[1, 2, 3, 4]);
    }
}
