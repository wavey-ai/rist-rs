//! Pure Rust RIST implementation surface.
//!
//! This module is available with the `pure-rust` feature. It exposes the
//! sans-I/O protocol core and the Mio UDP transport without going through
//! librist FFI.

pub mod core {
    pub use rist_core::*;
}

pub mod mio {
    pub use rist_mio::{
        MainMioReceiver, MainMioSender, RtpUdpSocket, SimpleMioReceiver, SimpleMioSender,
    };
}

pub use rist_core::{
    AesKeySize, Endpoint, MainControlPacket, MainOutboundPacket, MainReceiverCore,
    MainReceiverFeedback, MainSenderCore, NullPacketSuppression, OutboundPacket, PeerConfig,
    Profile, PskKey, ReceivedPayload, ReceiverStats, RecoveryConfig, SenderStats,
    SimpleReceiverCore, SimpleSenderCore,
};
