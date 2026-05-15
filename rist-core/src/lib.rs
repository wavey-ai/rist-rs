#![forbid(unsafe_code)]
//! Pure Rust RIST protocol primitives.
//!
//! This crate is deliberately sans-I/O. It owns packet parsing, sequence
//! arithmetic, URL configuration, and recovery state so the C bindings, a Mio
//! transport, and a Tokio transport can all share the same protocol core.

pub mod auth;
pub mod crypto;
pub mod endpoint;
pub mod error;
pub mod main_profile;
pub mod mpegts;
pub mod packet;
pub mod profile;
pub mod recovery;
pub mod sequence;
pub mod simple;
pub mod stats;
pub mod time;

pub use auth::{
    EapCode, EapPacket, EapSrpAuthenticatorSession, EapSrpChallenge, EapSrpClientSession,
    EapSrpMessage, EapSrpSubtype, EapolFrame, PassphraseRollover, SrpAuthenticator, SrpClient,
    SrpCredentialStore, SrpGroup, SrpHashVersion, SrpPassphrase, SrpUserRecord,
};
pub use crypto::{AesKeySize, PskKey};
pub use endpoint::{EncryptionConfig, Endpoint, PeerConfig, RecoveryConfig};
pub use error::Error;
pub use main_profile::{
    MainControlPacket, MainOutboundPacket, MainReceiverCore, MainReceiverFeedback, MainSenderCore,
};
pub use mpegts::{expand_null_packets, suppress_null_packets, NullPacketSuppression};
pub use profile::Profile;
pub use recovery::{MissingTracker, ReceiverObservation, SenderHistory};
pub use sequence::SequenceExtender;
pub use simple::{
    OutboundPacket, ReceivedPayload, RtcpIntervals, SimpleReceiverCore, SimpleSenderCore,
};
pub use stats::{ReceiverStats, SenderStats};

pub type Result<T> = std::result::Result<T, Error>;
