//! Statistics for RIST connections.

/// Re-export raw stats types for direct access.
pub use rist_sys::{rist_stats, rist_stats_receiver_flow, rist_stats_sender_peer};

/// Statistics for a receiver flow.
#[derive(Debug, Clone, Default)]
pub struct ReceiverStats {
    /// Number of connected peers.
    pub peer_count: u32,
    /// Flow ID.
    pub flow_id: u32,
    /// Current bandwidth in bps.
    pub bandwidth: usize,
    /// Retry bandwidth in bps.
    pub retry_bandwidth: usize,
    /// Total packets sent (NACKs).
    pub sent: u64,
    /// Total packets received.
    pub received: u64,
    /// Missing packets.
    pub missing: u32,
    /// Reordered packets.
    pub reordered: u32,
    /// Recovered packets.
    pub recovered: u32,
    /// Lost packets (unrecoverable).
    pub lost: u32,
    /// Quality percentage (0-100).
    pub quality: f64,
    /// Round-trip time in ms.
    pub rtt: u32,
}

impl From<&rist_sys::rist_stats_receiver_flow> for ReceiverStats {
    fn from(raw: &rist_sys::rist_stats_receiver_flow) -> Self {
        Self {
            peer_count: raw.peer_count,
            flow_id: raw.flow_id,
            bandwidth: raw.bandwidth,
            retry_bandwidth: raw.retry_bandwidth,
            sent: raw.sent,
            received: raw.received,
            missing: raw.missing,
            reordered: raw.reordered,
            recovered: raw.recovered,
            lost: raw.lost,
            quality: raw.quality,
            rtt: raw.rtt,
        }
    }
}

/// Statistics for a sender peer.
#[derive(Debug, Clone, Default)]
pub struct SenderStats {
    /// Peer ID.
    pub peer_id: u32,
    /// Current bandwidth in bps.
    pub bandwidth: usize,
    /// Retry bandwidth in bps.
    pub retry_bandwidth: usize,
    /// Total packets sent.
    pub sent: u64,
    /// Total packets received (ACKs).
    pub received: u64,
    /// Retransmitted packets.
    pub retransmitted: u64,
    /// Quality percentage (0-100).
    pub quality: f64,
    /// Round-trip time in ms.
    pub rtt: u32,
}

impl From<&rist_sys::rist_stats_sender_peer> for SenderStats {
    fn from(raw: &rist_sys::rist_stats_sender_peer) -> Self {
        Self {
            peer_id: raw.peer_id,
            bandwidth: raw.bandwidth,
            retry_bandwidth: raw.retry_bandwidth,
            sent: raw.sent,
            received: raw.received,
            retransmitted: raw.retransmitted,
            quality: raw.quality,
            rtt: raw.rtt,
        }
    }
}

