use crate::{Error, Result};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const PBKDF2_HMAC_SHA256_ITERATIONS: u32 = 1024;
pub const AES_BLOCK_SIZE: usize = 16;
pub const DEFAULT_KEY_ROTATION_PACKETS: u64 = 1_000_000;
pub const MAX_RECEIVE_REKEYS_PER_SECOND: u8 = 8;
/// Nonce changes (each one a PBKDF2 derivation) that all receive copies of
/// one key may make together in one second, while the copy's current
/// nonce has not carried a packet that passed the checks: every new
/// session of a listening receiver and every candidate source of a
/// listening sender draws on it. It bounds the CPU a flood of new nonces
/// costs, and how often a forger, who needs no key and may pick a new
/// nonce for every packet, gets a try at the checks, however many source
/// addresses and ports it uses.
///
/// A copy whose current nonce passed the checks (an established session
/// of a peer with the right passphrase) changes nonce under its own limit
/// of [`MAX_RECEIVE_REKEYS_PER_SECOND`] only, so a flood from other sources
/// can never hold up an established peer's nonce rotation. A forger gets
/// such a copy only by the chance a wrong key passes the checks (or by
/// replaying a correct peer's packet), and then only for one nonce change:
/// that nonce's first packet fails the checks and the copy is back on this
/// budget.
pub const MAX_SHARED_RECEIVE_REKEYS_PER_SECOND: u32 = 64;
/// Packets a transmit key encrypts under one nonce at most, whatever its
/// `key_rotation` (also 0, no rotation): the AES-CTR counter comes from
/// the 32-bit GRE sequence, so a nonce must change before the sequence
/// wraps or the keystream would repeat.
pub const MAX_PACKETS_PER_NONCE: u64 = 1 << 32;
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
    /// A packet a peer with the right passphrase may send but that this
    /// endpoint does not use (a RIST VSF subtype such as 0x8001, which
    /// librist also drops quietly, or a keepalive with an extension of a
    /// form it does not know): dropped, but it neither proves the nonce
    /// nor counts against it, so it can never shut a correct peer out.
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonceHealth {
    nonce: [u8; 4],
    proven: bool,
    failures: u8,
    latched: bool,
}

/// The receive-wide budget of [`MAX_SHARED_RECEIVE_REKEYS_PER_SECOND`],
/// shared by every clone of a key (so by every session's and candidate's
/// copy). It is not part of a key's identity: it never affects equality.
#[derive(Clone, Default)]
struct SharedRekeyBudget(Arc<Mutex<RekeyWindow>>);

#[derive(Default)]
struct RekeyWindow {
    start: Option<Instant>,
    used: u32,
}

impl SharedRekeyBudget {
    fn take(&self, now: Instant) -> bool {
        let mut window = match self.0.lock() {
            Ok(window) => window,
            Err(poisoned) => poisoned.into_inner(),
        };
        if window.start.map_or(true, |start| {
            now.duration_since(start) >= Duration::from_secs(1)
        }) {
            window.start = Some(now);
            window.used = 0;
        }
        if window.used >= MAX_SHARED_RECEIVE_REKEYS_PER_SECOND {
            return false;
        }
        window.used += 1;
        true
    }
}

impl PartialEq for SharedRekeyBudget {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for SharedRekeyBudget {}

/// The AES key of one nonce, derived (PBKDF2) on first use: a transmit
/// copy made for a new session derives nothing until the session sends,
/// so sessions a flood of forged packets creates cost no derivation of
/// their own. It is a function of the key size, passphrase and nonce,
/// which equality already compares, so it never affects equality.
#[derive(Clone, Default)]
struct AesKeySlot(Option<Zeroizing<Vec<u8>>>);

impl AesKeySlot {
    fn is_derived(&self) -> bool {
        self.0.is_some()
    }
}

impl PartialEq for AesKeySlot {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for AesKeySlot {}

#[derive(Clone, PartialEq, Eq)]
pub struct PskKey {
    key_size: AesKeySize,
    password: Zeroizing<Vec<u8>>,
    nonce: [u8; 4],
    key_rotation: u64,
    used_times: u64,
    aes_key: AesKeySlot,
    previous_nonce: Option<[u8; 4]>,
    previous_aes_key: AesKeySlot,
    rekey_window_start: Instant,
    rekeys_in_window: u8,
    nonce_health: [Option<NonceHealth>; TRACKED_NONCES],
    counters: PskReceiveCounters,
    shared_rekeys: SharedRekeyBudget,
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
        Ok(Self::build(key_size, password, key_rotation, nonce))
    }

    /// A key with a fresh history and its own receive-wide budget. Its
    /// AES key is derived on first use.
    fn build(
        key_size: AesKeySize,
        password: Zeroizing<Vec<u8>>,
        key_rotation: u64,
        nonce: [u8; 4],
    ) -> Self {
        Self {
            key_size,
            password,
            nonce,
            key_rotation,
            used_times: 0,
            aes_key: AesKeySlot::default(),
            previous_nonce: None,
            previous_aes_key: AesKeySlot::default(),
            rekey_window_start: Instant::now(),
            rekeys_in_window: 0,
            nonce_health: [None; TRACKED_NONCES],
            counters: PskReceiveCounters::default(),
            shared_rekeys: SharedRekeyBudget::default(),
        }
    }

    /// A transmit key for the same passphrase and key size, with a fresh
    /// nonce and the default rotation: what an endpoint that was given only
    /// a receive key encrypts with, so it never sends clear. It cannot
    /// fail: without the operating-system random source the nonce comes
    /// from a process-wide counter (see [`Self::fresh_sender_copy`]).
    pub fn sender_for(&self) -> Self {
        let mut key = self.fresh_sender_copy();
        key.key_rotation = DEFAULT_KEY_ROTATION_PACKETS;
        key
    }

    /// A receive key for the same passphrase and key size, with its own
    /// receive-wide budget: what an endpoint that was given only a
    /// transmit key decrypts with, so it drops clear packets from its peer.
    pub fn receiver_for(&self) -> Self {
        Self::build(self.key_size, self.password.clone(), 0, [0; 4])
    }

    /// A transmit key for a new peer or session: the same passphrase, key
    /// size and rotation, but its own fresh random nonce (so its own AES
    /// key), unused, with no receive history.
    ///
    /// The AES-CTR IV of RIST Main PSK comes only from the GRE version and
    /// sequence, and every peer state or session starts its GRE sequence at
    /// 0, so two peers or sessions that shared one nonce would encrypt
    /// different packets with the same keystream. Each one gets its own
    /// copy from here. A receiver takes any nonce from each sender, as
    /// librist does.
    ///
    /// The nonce is picked here; its AES key is derived on the first
    /// encryption, so a session that never sends never derives one.
    pub fn fresh_sender_copy(&self) -> Self {
        let mut nonce = [0; 4];
        let mut fresh = false;
        for _ in 0..8 {
            if getrandom::getrandom(&mut nonce).is_ok() && nonce != [0; 4] && nonce != self.nonce {
                fresh = true;
                break;
            }
        }
        if !fresh {
            // The operating-system CSPRNG is unavailable: a process-wide
            // counter still gives every copy a distinct nonce (uniqueness,
            // not secrecy, is what CTR needs from it).
            nonce = fallback_distinct_nonce(self.nonce);
        }
        Self {
            key_size: self.key_size,
            password: self.password.clone(),
            nonce,
            key_rotation: self.key_rotation,
            used_times: 0,
            aes_key: AesKeySlot::default(),
            previous_nonce: None,
            previous_aes_key: AesKeySlot::default(),
            rekey_window_start: Instant::now(),
            rekeys_in_window: 0,
            nonce_health: [None; TRACKED_NONCES],
            counters: PskReceiveCounters::default(),
            shared_rekeys: self.shared_rekeys.clone(),
        }
    }

    /// This key with its receive history and counters cleared, for a new
    /// session. The copy draws on the same receive-wide budget of nonce
    /// changes ([`MAX_SHARED_RECEIVE_REKEYS_PER_SECOND`]) as this key and
    /// every other copy of it.
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

    /// Adds counters from another copy of this key (a receive state that
    /// is being dropped or replaced), so they are not lost.
    pub fn absorb_counters(&mut self, counters: PskReceiveCounters) {
        self.counters.add(counters);
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
    /// An ignored one leaves no trace.
    pub fn record_verdict(&mut self, nonce: [u8; 4], verdict: DecryptVerdict) {
        if verdict == DecryptVerdict::Ignore {
            return;
        }
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
            DecryptVerdict::Weak | DecryptVerdict::Ignore => {}
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

    /// Whether this copy's current nonce carried a packet that passed the
    /// checks and is not shut out: the copy is an established session of a
    /// peer with the right passphrase (or, by the chance a wrong key passes
    /// the checks, a forger's for one nonce).
    fn current_nonce_proven(&self) -> bool {
        self.nonce_health
            .iter()
            .flatten()
            .any(|health| health.nonce == self.nonce && health.proven && !health.latched)
    }

    /// Whether a nonce this copy still tracks carried a packet with a
    /// [`DecryptVerdict::Strong`] verdict (checked RTP data or RTCP) and is
    /// not shut out. A receive state is proven this way only by a peer with
    /// the right passphrase (or, by the chance a wrong key passes the
    /// checks, about one forged nonce in 2^15). Keepalives, buffer
    /// negotiation and out-of-band packets get a [`DecryptVerdict::Weak`]
    /// verdict, which a host with no key can earn every time: a receive
    /// state that has seen only those is never proven. An endpoint uses
    /// this to decide whether a session is a peer at all: whether it may
    /// become the one feedback and keepalives go to, and whether it is sent
    /// anything.
    ///
    /// Two nonces are tracked, so the peer's own nonce renewal keeps the
    /// state proven while the new nonce has carried only keepalives.
    pub fn receive_proven(&self) -> bool {
        self.nonce_health
            .iter()
            .flatten()
            .any(|health| health.proven && !health.latched)
    }

    /// Makes `nonce` the receive nonce, deriving its AES key. Every change
    /// counts against this copy's [`MAX_RECEIVE_REKEYS_PER_SECOND`]; while
    /// the current nonce is not proven (see [`Self::current_nonce_proven`])
    /// it also takes a slot of the receive-wide
    /// [`MAX_SHARED_RECEIVE_REKEYS_PER_SECOND`].
    pub fn set_nonce(&mut self, nonce: [u8; 4]) -> Result<()> {
        if nonce == [0; 4] {
            return Err(Error::InvalidPskNonce);
        }
        // A nonce whose key is not derived yet (a copy that has not used
        // it) costs a derivation like any change, so it is counted as one.
        if self.nonce != nonce || !self.aes_key.is_derived() {
            let now = Instant::now();
            if now.duration_since(self.rekey_window_start) >= Duration::from_secs(1) {
                self.rekey_window_start = now;
                self.rekeys_in_window = 0;
            }
            if self.rekeys_in_window >= MAX_RECEIVE_REKEYS_PER_SECOND
                || (!self.current_nonce_proven() && !self.shared_rekeys.take(now))
            {
                return Err(Error::PskRekeyRateLimited);
            }
            self.rekeys_in_window += 1;
            if self.nonce != nonce {
                let keep_previous = self.nonce != [0; 4] && self.aes_key.is_derived();
                self.previous_nonce = keep_previous.then_some(self.nonce);
                self.previous_aes_key = if keep_previous {
                    std::mem::take(&mut self.aes_key)
                } else {
                    AesKeySlot::default()
                };
            }
            self.nonce = nonce;
            self.aes_key = AesKeySlot(Some(Zeroizing::new(derive_aes_key(
                self.key_size,
                &self.password,
                &self.nonce,
            ))));
            self.used_times = 0;
        }
        Ok(())
    }

    /// The AES key of the current nonce, derived now if it has not been.
    fn current_aes_key(&mut self) -> &[u8] {
        let (key_size, password, nonce) = (self.key_size, &self.password, &self.nonce);
        self.aes_key
            .0
            .get_or_insert_with(|| Zeroizing::new(derive_aes_key(key_size, password, nonce)))
    }

    /// Whether the AES key of the current nonce has been derived.
    pub fn aes_key_derived(&self) -> bool {
        self.aes_key.is_derived()
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
                .0
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
        // A receive key follows the sender's nonce: it never rotates its own.
        let key_size = self.key_size;
        Ok(crypt_with_key(
            key_size,
            self.current_aes_key(),
            gre_version,
            sequence,
            input,
        ))
    }

    /// Packets this key encrypts under one nonce before it renews it:
    /// `key_rotation`, but never more than [`MAX_PACKETS_PER_NONCE`].
    fn packets_per_nonce(&self) -> u64 {
        if self.key_rotation == 0 {
            MAX_PACKETS_PER_NONCE
        } else {
            self.key_rotation.min(MAX_PACKETS_PER_NONCE)
        }
    }

    fn crypt(&mut self, gre_version: u8, sequence: u32, input: &[u8]) -> Vec<u8> {
        if self.used_times >= self.packets_per_nonce() {
            self.advance_nonce();
            self.aes_key = AesKeySlot::default();
            self.used_times = 0;
        }

        let key_size = self.key_size;
        let out = crypt_with_key(
            key_size,
            self.current_aes_key(),
            gre_version,
            sequence,
            input,
        );
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
        // The operating-system CSPRNG is unavailable. Keeping the nonce
        // would repeat keystream (the GRE sequence goes on from where it
        // is, and may wrap); a counter-derived nonce keeps it unique, which
        // is what CTR needs.
        self.nonce = fallback_distinct_nonce(current);
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

fn fallback_distinct_nonce(base: [u8; 4]) -> [u8; 4] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    loop {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = u32::from_be_bytes(base).wrapping_add(step).to_be_bytes();
        if nonce != [0; 4] && nonce != base {
            return nonce;
        }
    }
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

    /// Only a Strong verdict proves a receive state: keepalives (which a
    /// host with no key gets through every time) never do, a latched nonce
    /// no longer counts, and the peer's renewal to a new nonce keeps it.
    #[test]
    fn only_a_strong_verdict_proves_a_receive_state() {
        let template = PskKey::receiver(128, b"secret").unwrap();
        let mut rx = template.fresh_copy();
        assert!(!rx.receive_proven());
        for _ in 0..1000 {
            rx.record_verdict([9, 9, 9, 9], DecryptVerdict::Weak);
        }
        rx.record_verdict([9, 9, 9, 9], DecryptVerdict::Ignore);
        assert!(!rx.receive_proven());

        let peer = [1, 0, 0, 1];
        rx.record_verdict(peer, DecryptVerdict::Strong);
        assert!(rx.receive_proven());
        // The peer renews its nonce and sends a keepalive first.
        rx.record_verdict([1, 0, 0, 2], DecryptVerdict::Weak);
        assert!(rx.receive_proven());
        // A fresh copy for another source starts unproven.
        assert!(!rx.fresh_copy().receive_proven());

        // A lucky forged nonce that then fails the checks is shut out, and
        // with it the proof.
        let mut lucky = template.fresh_copy();
        lucky.record_verdict([3, 0, 0, 1], DecryptVerdict::Strong);
        assert!(lucky.receive_proven());
        for _ in 0..PSK_BAD_DECRYPTION_LIMIT {
            lucky.record_verdict([3, 0, 0, 1], DecryptVerdict::Bad);
        }
        assert!(!lucky.receive_proven());
    }

    #[test]
    fn sender_for_a_receive_key_encrypts_for_the_same_passphrase() {
        let rx_template = PskKey::receiver(192, b"secret").unwrap();
        let mut tx = rx_template.sender_for();
        assert_eq!(tx.key_size(), AesKeySize::Aes192);
        assert_ne!(tx.nonce(), [0; 4]);
        let nonce = tx.nonce();
        let encrypted = tx.encrypt(1, 9, b"payload");
        let mut rx = rx_template.fresh_copy();
        assert_eq!(rx.decrypt(nonce, 1, 9, &encrypted).unwrap(), b"payload");
    }

    /// Two transmit copies of one key never share a nonce (and so never
    /// share the AES-CTR keystream at the same GRE sequence), keep the
    /// size and rotation, and decrypt with the same passphrase.
    #[test]
    fn fresh_sender_copies_have_their_own_nonce_and_keystream() {
        let base = PskKey::with_key_rotation(256, 50, b"secret").unwrap();
        let mut a = base.fresh_sender_copy();
        let mut b = base.fresh_sender_copy();
        assert_ne!(a.nonce(), base.nonce());
        assert_ne!(b.nonce(), base.nonce());
        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.nonce(), [0; 4]);
        assert_eq!(a.key_size(), AesKeySize::Aes256);
        assert_eq!(a.key_rotation, 50);
        assert_eq!(a.used_times, 0);
        let plain_a = [0x47u8; 188];
        let plain_b = [0x11u8; 188];
        let ct_a = a.encrypt(1, 0, &plain_a);
        let ct_b = b.encrypt(1, 0, &plain_b);
        let xor_ct: Vec<u8> = ct_a.iter().zip(&ct_b).map(|(x, y)| x ^ y).collect();
        let xor_pt: Vec<u8> = plain_a.iter().zip(&plain_b).map(|(x, y)| x ^ y).collect();
        assert_ne!(xor_ct, xor_pt, "two copies reused one keystream");
        let mut rx = PskKey::receiver(256, b"secret").unwrap();
        assert_eq!(rx.decrypt(a.nonce(), 1, 0, &ct_a).unwrap(), plain_a);
        assert_eq!(rx.decrypt(b.nonce(), 1, 0, &ct_b).unwrap(), plain_b);
        // Many copies: all distinct.
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(nonces.insert(base.fresh_sender_copy().nonce()));
        }
    }

    /// `sender_for` never fails and never hands back a key that sends
    /// clear: it is a real transmit key with the default rotation and its
    /// own nonce; `receiver_for` decrypts what a transmit key sends.
    #[test]
    fn sender_for_and_receiver_for_cannot_fail() {
        let tx = PskKey::with_key_rotation(256, 7, b"secret").unwrap();
        let mut rx = tx.receiver_for();
        assert_eq!(rx.key_size(), AesKeySize::Aes256);
        assert_eq!(rx.nonce(), [0; 4]);
        let mut tx = tx;
        let nonce = tx.nonce();
        let encrypted = tx.encrypt(2, 1, b"payload");
        assert_eq!(rx.decrypt(nonce, 2, 1, &encrypted).unwrap(), b"payload");
        let sender = rx.sender_for();
        assert_eq!(sender.key_rotation, DEFAULT_KEY_ROTATION_PACKETS);
        assert_ne!(sender.nonce(), [0; 4]);
        assert_eq!(sender.key_size(), AesKeySize::Aes256);
    }

    /// Whatever `key_rotation` says (0, no rotation, or more than the
    /// 32-bit GRE sequence holds), a transmit key renews its nonce before
    /// 2^32 packets, so the sequence never wraps under one nonce.
    #[test]
    fn transmit_nonce_renews_before_the_gre_sequence_wraps() {
        for rotation in [0, MAX_PACKETS_PER_NONCE + 1, u64::MAX] {
            let mut tx = PskKey::with_key_rotation(128, rotation, b"secret").unwrap();
            let first = tx.nonce();
            tx.used_times = MAX_PACKETS_PER_NONCE - 1;
            tx.encrypt(2, u32::MAX, b"last under this nonce");
            assert_eq!(tx.nonce(), first, "rotation {rotation}");
            tx.encrypt(2, 0, b"sequence wrapped");
            assert_ne!(tx.nonce(), first, "rotation {rotation}");
            assert_ne!(tx.nonce(), [0; 4]);
            assert_eq!(tx.used_times, 1);
        }
        // A smaller rotation still applies as set.
        let mut tx = PskKey::with_key_rotation(128, 3, b"secret").unwrap();
        let first = tx.nonce();
        for sequence in 0..3 {
            tx.encrypt(2, sequence, b"x");
        }
        assert_eq!(tx.nonce(), first);
        tx.encrypt(2, 3, b"x");
        assert_ne!(tx.nonce(), first);
    }

    /// A receive key never rotates its own nonce, even one made with a
    /// rotation: it follows the sender's, with one derivation for it.
    #[test]
    fn receive_key_follows_the_sender_nonce_without_rotating() {
        let mut tx = PskKey::with_key_rotation(128, 1_000_000, b"secret").unwrap();
        let mut rx = PskKey::with_key_rotation(128, 2, b"secret").unwrap();
        let nonce = tx.nonce();
        for sequence in 0..32 {
            let encrypted = tx.encrypt(2, sequence, b"payload");
            assert_eq!(
                rx.decrypt(nonce, 2, sequence, &encrypted).unwrap(),
                b"payload"
            );
        }
        assert_eq!(rx.nonce(), nonce);
        assert_eq!(rx.rekeys_in_window, 1);
    }

    /// Every copy of one receive key (every session or candidate source)
    /// draws on one budget of nonce changes a second: a forger that spreads
    /// new nonces over many sessions gets no more tries, and costs no more
    /// derivations, than the budget allows.
    #[test]
    fn copies_of_a_receive_key_share_one_budget_of_nonce_changes() {
        let template = PskKey::receiver(128, b"secret").unwrap();
        let per_key = u32::from(MAX_RECEIVE_REKEYS_PER_SECOND);
        let sessions = MAX_SHARED_RECEIVE_REKEYS_PER_SECOND / per_key + 2;
        let mut accepted = 0;
        let mut refused = 0;
        let mut next = 1u32;
        for _ in 0..sessions {
            let mut session = template.fresh_copy();
            for _ in 0..per_key {
                match session.set_nonce(next.to_be_bytes()) {
                    Ok(()) => accepted += 1,
                    Err(Error::PskRekeyRateLimited) => refused += 1,
                    Err(other) => panic!("unexpected {other:?}"),
                }
                next += 1;
            }
        }
        assert_eq!(accepted, MAX_SHARED_RECEIVE_REKEYS_PER_SECOND);
        assert_eq!(
            refused,
            sessions * per_key - MAX_SHARED_RECEIVE_REKEYS_PER_SECOND
        );
        // A key made on its own (another endpoint) has its own budget.
        let mut other = PskKey::receiver(128, b"secret").unwrap();
        other.set_nonce([9, 9, 9, 9]).unwrap();
        // So does a receive key derived for an endpoint given only a
        // transmit key.
        let mut derived = PskKey::new(128, b"secret").unwrap().receiver_for();
        derived.set_nonce([9, 9, 9, 9]).unwrap();
        // The budget refills after a second.
        let mut late = template.fresh_copy();
        late.shared_rekeys.0.lock().unwrap().start = Some(Instant::now() - Duration::from_secs(2));
        late.set_nonce([8, 8, 8, 8]).unwrap();
        // It is not part of a key's identity.
        assert_eq!(template.fresh_copy(), template.fresh_copy());
    }

    /// Uses up the receive-wide budget of `template` with copies of it,
    /// as a flood of new nonces from many sources would.
    /// Holds every one-second window of `template` and its later copies
    /// open, so a slow (debug, loaded) run never sees a window refill
    /// part-way through a test.
    fn freeze_windows(template: &mut PskKey) {
        let far = Instant::now() + Duration::from_secs(3600);
        template.rekey_window_start = far;
        let mut window = template.shared_rekeys.0.lock().unwrap();
        window.start = Some(far);
        window.used = 0;
    }

    fn exhaust_shared_budget(template: &PskKey, next: &mut u32) {
        // Each flood source is a fresh copy: its first change needs a
        // slot of the shared budget, so the first refusal means it is used up.
        for _ in 0..=MAX_SHARED_RECEIVE_REKEYS_PER_SECOND {
            let mut flood = template.fresh_copy();
            *next += 1;
            if flood.set_nonce(next.to_be_bytes()).is_err() {
                return;
            }
        }
        panic!("the shared budget never ran out");
    }

    /// Review 3, defect 1: a copy whose current nonce passed the checks (an
    /// established peer) changes nonce under its own per-session limit and
    /// never waits on the receive-wide budget, so a flood of new nonces from
    /// other sources cannot hold up its rotation. A copy whose current
    /// nonce failed the checks is back on the shared budget at once.
    #[test]
    fn an_established_peer_rotates_while_a_flood_holds_the_shared_budget() {
        let mut template = PskKey::receiver(128, b"secret").unwrap();
        freeze_windows(&mut template);
        let mut next = 0x1000_0000u32;

        let mut established = template.fresh_copy();
        established.set_nonce([1, 0, 0, 1]).unwrap();
        established.record_verdict([1, 0, 0, 1], DecryptVerdict::Strong);

        exhaust_shared_budget(&template, &mut next);

        // A new session waits for the budget: a new peer's first packets
        // can be delayed by the flood.
        let mut newcomer = template.fresh_copy();
        assert_eq!(
            newcomer.set_nonce([2, 0, 0, 2]),
            Err(Error::PskRekeyRateLimited)
        );

        // The established session rotates under its own limit (it used
        // one change to start), each new nonce proven by its first packet.
        for n in 2..=MAX_RECEIVE_REKEYS_PER_SECOND {
            let nonce = [1, 0, 0, n];
            established.set_nonce(nonce).unwrap();
            established.record_verdict(nonce, DecryptVerdict::Strong);
        }
        // The per-session limit still holds.
        assert_eq!(
            established.set_nonce([1, 0, 0, 0xff]),
            Err(Error::PskRekeyRateLimited)
        );

        // A forger's session whose nonce once passed by chance gets one
        // change outside the budget; that nonce fails the checks, and the
        // next change waits on the budget again.
        let mut lucky = template.fresh_copy();
        lucky.shared_rekeys.0.lock().unwrap().used = 0;
        lucky.set_nonce([3, 0, 0, 1]).unwrap();
        lucky.record_verdict([3, 0, 0, 1], DecryptVerdict::Strong);
        exhaust_shared_budget(&template, &mut next);
        lucky.set_nonce([3, 0, 0, 2]).unwrap();
        lucky.record_verdict([3, 0, 0, 2], DecryptVerdict::Bad);
        assert_eq!(
            lucky.set_nonce([3, 0, 0, 3]),
            Err(Error::PskRekeyRateLimited)
        );
        // Returning to the proven nonce is a change like any other (the
        // previous nonce was the latched one), so it waits too.
        assert_eq!(
            lucky.set_nonce([3, 0, 0, 1]),
            Err(Error::PskRekeyRateLimited)
        );
    }

    /// Review 3, defect 2: a transmit copy for a new session picks its
    /// nonce at once but derives its AES key only on its first
    /// encryption, so a session that never sends costs no derivation; nor
    /// does a receive key before its first nonce.
    #[test]
    fn copies_derive_their_aes_key_on_first_use_only() {
        let base = PskKey::with_key_rotation(128, 3, b"secret").unwrap();
        assert!(!base.aes_key_derived());
        let rx_template = base.receiver_for();
        assert!(!rx_template.aes_key_derived());
        assert!(!PskKey::receiver(128, b"secret").unwrap().aes_key_derived());
        assert!(!rx_template.sender_for().aes_key_derived());

        let mut copy = base.fresh_sender_copy();
        assert!(!copy.aes_key_derived());
        assert_ne!(copy.nonce(), [0; 4]);
        let nonce = copy.nonce();
        let encrypted = copy.encrypt(2, 0, b"payload");
        assert!(copy.aes_key_derived());
        assert_eq!(copy.nonce(), nonce);
        let mut rx = rx_template.fresh_copy();
        assert_eq!(rx.decrypt(nonce, 2, 0, &encrypted).unwrap(), b"payload");
        assert!(rx.aes_key_derived());

        // A rotation picks the next nonce and derives it on that packet.
        for sequence in 1..3 {
            copy.encrypt(2, sequence, b"x");
        }
        let rotated = copy.encrypt(2, 3, b"rotated");
        assert_ne!(copy.nonce(), nonce);
        assert!(copy.aes_key_derived());
        assert_eq!(
            rx.decrypt(copy.nonce(), 2, 3, &rotated).unwrap(),
            b"rotated"
        );
        // The receiver kept the key of the nonce before.
        assert_eq!(rx.decrypt(nonce, 2, 0, &encrypted).unwrap(), b"payload");

        // A key whose own nonce is not derived yet (one used both ways)
        // pays for that nonce like any change: never a derivation outside
        // the budget, even for packets that carry its nonce.
        let mut template = PskKey::new(128, b"secret").unwrap();
        freeze_windows(&mut template);
        let own = template.nonce();
        let mut next = 0x2000_0000u32;
        exhaust_shared_budget(&template, &mut next);
        let mut session = template.fresh_copy();
        assert_eq!(
            session.decrypt(own, 2, 0, b"anything"),
            Err(Error::PskRekeyRateLimited)
        );
        assert!(!session.aes_key_derived());
    }

    #[test]
    fn fallback_nonces_are_distinct_and_never_zero() {
        let base = [0xff, 0xff, 0xff, 0xff];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let nonce = fallback_distinct_nonce(base);
            assert_ne!(nonce, [0; 4]);
            assert_ne!(nonce, base);
            assert!(seen.insert(nonce));
        }
    }
}
