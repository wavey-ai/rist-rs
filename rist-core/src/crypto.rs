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
/// Consecutive packets of one nonce that may fail the checks after
/// decryption before that nonce is shut out, once the nonce has carried a
/// packet that passed them. librist latches on the seventh failure in a
/// row (`bad_count++ > 5`); so does this.
pub const PSK_BAD_DECRYPTION_LIMIT: u8 = 7;
/// The same limit for a nonce that has not yet carried a packet that
/// passed the checks: a sender with the right passphrase passes them from
/// its first packet, so the first failure shuts the nonce out.
pub const PSK_UNPROVEN_BAD_DECRYPTION_LIMIT: u8 = 1;
/// Nonces whose check history a receive key keeps (the current one and
/// the one before a rotation).
const TRACKED_NONCES: usize = 2;

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

/// What a receive key turned away: an endpoint with a key drops clear
/// packets (other than EAPOL) and encrypted packets that fail the checks
/// RIST Main PSK allows after decryption. Additive counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PskReceiveCounters {
    /// Unencrypted packets (not EAPOL) dropped because a key is configured.
    pub clear_packets_dropped: u64,
    /// Encrypted packets dropped because they failed the PSK checks: a
    /// malformed encrypted header, a refused nonce change, or decrypted
    /// contents that are not a valid RIST packet (a wrong passphrase, or a
    /// forged or damaged packet).
    pub decrypt_rejected: u64,
    /// Encrypted packets dropped without decryption because their nonce
    /// was shut out after failed checks (see [`PSK_BAD_DECRYPTION_LIMIT`]).
    pub decrypt_latched: u64,
    /// Times a nonce was shut out.
    pub nonce_latches: u64,
}

impl PskReceiveCounters {
    pub fn add(&mut self, other: Self) {
        self.clear_packets_dropped += other.clear_packets_dropped;
        self.decrypt_rejected += other.decrypt_rejected;
        self.decrypt_latched += other.decrypt_latched;
        self.nonce_latches += other.nonce_latches;
    }
}

/// How the contents of one decrypted packet fared in the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptVerdict {
    /// A structure a wrong key reproduces only by chance (an RTP or RTCP
    /// header and lengths): proves the nonce.
    Strong,
    /// Accepted, but with too little structure to prove anything
    /// (keepalive, buffer negotiation, out-of-band data).
    Weak,
    /// Not a valid RIST packet.
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonceHealth {
    nonce: [u8; 4],
    proven: bool,
    failures: u8,
    latched: bool,
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
    nonce_health: [Option<NonceHealth>; TRACKED_NONCES],
    counters: PskReceiveCounters,
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
            nonce_health: [None; TRACKED_NONCES],
            counters: PskReceiveCounters::default(),
        })
    }

    /// A transmit key for the same passphrase and key size, with a fresh
    /// random nonce and the default rotation: what an endpoint that was
    /// given only a receive key encrypts with, so it never sends clear.
    pub fn sender_for(&self) -> Result<Self> {
        Self::with_key_rotation(
            self.key_size.bits(),
            DEFAULT_KEY_ROTATION_PACKETS,
            self.password.as_slice(),
        )
    }

    /// A receive key for the same passphrase and key size: what an
    /// endpoint that was given only a transmit key decrypts with, so it
    /// drops clear packets from its peer.
    pub fn receiver_for(&self) -> Result<Self> {
        Self::receiver(self.key_size.bits(), self.password.as_slice())
    }

    /// This key with its receive history and counters cleared, for a new
    /// session.
    pub fn fresh_copy(&self) -> Self {
        let mut key = self.clone();
        key.nonce_health = [None; TRACKED_NONCES];
        key.counters = PskReceiveCounters::default();
        key
    }

    /// What this key turned away as a receive key.
    pub fn receive_counters(&self) -> PskReceiveCounters {
        self.counters
    }

    /// Counts a clear packet dropped because this key is configured.
    pub fn note_clear_dropped(&mut self) {
        self.counters.clear_packets_dropped += 1;
    }

    /// Counts an encrypted packet rejected before or during decryption.
    pub fn note_rejected(&mut self) {
        self.counters.decrypt_rejected += 1;
    }

    /// Whether packets of `nonce` are shut out. Counts the packet as
    /// dropped when they are.
    pub fn refuse_latched(&mut self, nonce: [u8; 4]) -> Result<()> {
        if self
            .nonce_health
            .iter()
            .flatten()
            .any(|health| health.nonce == nonce && health.latched)
        {
            self.counters.decrypt_latched += 1;
            return Err(Error::PskNonceLatched);
        }
        Ok(())
    }

    /// Records how a packet of `nonce` fared in the checks after
    /// decryption. A bad one is counted in `decrypt_rejected`; enough bad
    /// ones in a row shut the nonce out until the sender's nonce changes.
    pub fn record_verdict(&mut self, nonce: [u8; 4], verdict: DecryptVerdict) {
        let index = match self
            .nonce_health
            .iter()
            .position(|health| health.is_some_and(|health| health.nonce == nonce))
        {
            Some(index) => index,
            None => {
                // Newest first: the oldest tracked nonce makes room.
                self.nonce_health.rotate_right(1);
                self.nonce_health[0] = Some(NonceHealth {
                    nonce,
                    proven: false,
                    failures: 0,
                    latched: false,
                });
                0
            }
        };
        let health = self.nonce_health[index]
            .as_mut()
            .expect("tracked nonce was just found or inserted");
        match verdict {
            DecryptVerdict::Strong => {
                health.proven = true;
                health.failures = 0;
            }
            DecryptVerdict::Weak => {}
            DecryptVerdict::Bad => {
                self.counters.decrypt_rejected += 1;
                health.failures = health.failures.saturating_add(1);
                let limit = if health.proven {
                    PSK_BAD_DECRYPTION_LIMIT
                } else {
                    PSK_UNPROVEN_BAD_DECRYPTION_LIMIT
                };
                if !health.latched && health.failures >= limit {
                    health.latched = true;
                    self.counters.nonce_latches += 1;
                }
            }
        }
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
            .field("counters", &self.counters)
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

    #[test]
    fn nonce_latch_follows_librist_once_proven_and_is_strict_before() {
        let mut rx = PskKey::receiver(128, b"secret").unwrap();
        let proven = [1, 1, 1, 1];
        rx.record_verdict(proven, DecryptVerdict::Strong);
        // Six failures in a row are tolerated, and a good packet clears them.
        for _ in 0..PSK_BAD_DECRYPTION_LIMIT - 1 {
            rx.record_verdict(proven, DecryptVerdict::Bad);
        }
        assert!(rx.refuse_latched(proven).is_ok());
        rx.record_verdict(proven, DecryptVerdict::Strong);
        for _ in 0..PSK_BAD_DECRYPTION_LIMIT - 1 {
            rx.record_verdict(proven, DecryptVerdict::Bad);
        }
        assert!(rx.refuse_latched(proven).is_ok());
        // A keepalive proves nothing and clears nothing.
        rx.record_verdict(proven, DecryptVerdict::Weak);
        // The seventh in a row shuts the nonce out.
        rx.record_verdict(proven, DecryptVerdict::Bad);
        assert_eq!(rx.refuse_latched(proven), Err(Error::PskNonceLatched));
        assert_eq!(rx.receive_counters().nonce_latches, 1);
        assert_eq!(
            rx.receive_counters().decrypt_rejected,
            u64::from(2 * PSK_BAD_DECRYPTION_LIMIT - 1)
        );
        assert_eq!(rx.receive_counters().decrypt_latched, 1);

        // A nonce that never passed a check is shut out at its first failure,
        // even after keepalives.
        let unproven = [2, 2, 2, 2];
        rx.record_verdict(unproven, DecryptVerdict::Weak);
        assert!(rx.refuse_latched(unproven).is_ok());
        rx.record_verdict(unproven, DecryptVerdict::Bad);
        assert_eq!(rx.refuse_latched(unproven), Err(Error::PskNonceLatched));

        // Two nonces are tracked: a third one pushes the oldest out, and
        // that nonce starts over (as librist resets on a nonce change).
        let third = [3, 3, 3, 3];
        rx.record_verdict(third, DecryptVerdict::Strong);
        assert!(rx.refuse_latched(proven).is_ok());
        assert_eq!(rx.refuse_latched(unproven), Err(Error::PskNonceLatched));

        // A fresh copy for a new session forgets all of it.
        let fresh = rx.fresh_copy();
        assert_eq!(fresh.receive_counters(), PskReceiveCounters::default());
        let mut fresh = fresh;
        assert!(fresh.refuse_latched(unproven).is_ok());
    }

    #[test]
    fn sender_for_a_receive_key_encrypts_for_the_same_passphrase() {
        let rx_template = PskKey::receiver(192, b"secret").unwrap();
        let mut tx = rx_template.sender_for().unwrap();
        assert_eq!(tx.key_size(), AesKeySize::Aes192);
        assert_ne!(tx.nonce(), [0; 4]);
        let nonce = tx.nonce();
        let encrypted = tx.encrypt(1, 9, b"payload");
        let mut rx = rx_template.fresh_copy();
        assert_eq!(rx.decrypt(nonce, 1, 9, &encrypted).unwrap(), b"payload");
    }
}
