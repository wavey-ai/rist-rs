use rist_core::packet::gre::ReducedPacket;
use rist_core::packet::rtcp::decode_nacks_from_compound;
use rist_core::packet::rtp::{RtpPacket, RTP_PAYLOAD_TYPE_MPEGTS, RTP_PAYLOAD_TYPE_RIST};
use rist_core::sequence::extend_near;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};

const MAX_DATAGRAM_SIZE: usize = 65_536;
const MAX_DATAGRAMS_PER_POLL: usize = 512;
const MAX_TRACKED_DROPS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct LossProxyConfig {
    pub listen: SocketAddr,
    pub upstream_bind: SocketAddr,
    pub target: SocketAddr,
    pub drop_every: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LossProxyStats {
    pub source_datagrams: u64,
    pub source_bytes: u64,
    pub media_first_transmissions: u64,
    pub injected_drops: u64,
    pub recovered_forwards: u64,
    pub expired_drops: u64,
    pub forwarded_source_datagrams: u64,
    pub feedback_datagrams: u64,
    pub feedback_bytes: u64,
    pub nack_requests: u64,
}

impl LossProxyStats {
    pub fn all_injected_drops_recovered(self) -> bool {
        self.injected_drops > 0 && self.recovered_forwards == self.injected_drops
    }
}

pub struct LossProxy {
    source_socket: UdpSocket,
    receiver_socket: UdpSocket,
    target: SocketAddr,
    source: Option<SocketAddr>,
    drop_every: u64,
    highest_media_sequence: Option<u32>,
    dropped_sequences: HashSet<u32>,
    dropped_sequence_order: VecDeque<u32>,
    last_nack_sequences: Vec<u32>,
    stats: LossProxyStats,
    receive_buffer: Vec<u8>,
}

impl LossProxy {
    pub fn bind(config: LossProxyConfig) -> io::Result<Self> {
        ensure_same_address_family(config.listen, config.target)?;
        ensure_same_address_family(config.upstream_bind, config.target)?;
        let source_socket = UdpSocket::bind(config.listen)?;
        let receiver_socket = UdpSocket::bind(config.upstream_bind)?;
        source_socket.set_nonblocking(true)?;
        receiver_socket.set_nonblocking(true)?;
        Ok(Self {
            source_socket,
            receiver_socket,
            target: config.target,
            source: None,
            drop_every: config.drop_every,
            highest_media_sequence: None,
            dropped_sequences: HashSet::new(),
            dropped_sequence_order: VecDeque::new(),
            last_nack_sequences: Vec::new(),
            stats: LossProxyStats::default(),
            receive_buffer: vec![0; MAX_DATAGRAM_SIZE],
        })
    }

    pub fn listen_addr(&self) -> io::Result<SocketAddr> {
        self.source_socket.local_addr()
    }

    pub fn upstream_addr(&self) -> io::Result<SocketAddr> {
        self.receiver_socket.local_addr()
    }

    pub fn stats(&self) -> LossProxyStats {
        self.stats
    }

    pub fn last_nack_sequences(&self) -> &[u32] {
        &self.last_nack_sequences
    }

    pub fn poll(&mut self) -> io::Result<usize> {
        let mut processed = 0;
        processed += self.poll_source()?;
        processed += self.poll_receiver()?;
        Ok(processed)
    }

    fn poll_source(&mut self) -> io::Result<usize> {
        let mut processed = 0;
        while processed < MAX_DATAGRAMS_PER_POLL {
            let (len, source) = match self.source_socket.recv_from(&mut self.receive_buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            };
            processed += 1;
            self.source = Some(source);
            self.stats.source_datagrams += 1;
            self.stats.source_bytes += len as u64;

            let media_sequence = media_sequence(&self.receive_buffer[..len]);
            if self.should_drop(media_sequence) {
                continue;
            }
            self.receiver_socket
                .send_to(&self.receive_buffer[..len], self.target)?;
            self.stats.forwarded_source_datagrams += 1;
        }
        Ok(processed)
    }

    fn poll_receiver(&mut self) -> io::Result<usize> {
        let mut processed = 0;
        while processed < MAX_DATAGRAMS_PER_POLL {
            let (len, _receiver) = match self.receiver_socket.recv_from(&mut self.receive_buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            };
            processed += 1;
            self.stats.feedback_datagrams += 1;
            self.stats.feedback_bytes += len as u64;
            self.record_nacks(len);
            if let Some(source) = self.source {
                self.source_socket
                    .send_to(&self.receive_buffer[..len], source)?;
            }
        }
        Ok(processed)
    }

    fn record_nacks(&mut self, len: usize) {
        let Some(nacks) = ReducedPacket::decode(&self.receive_buffer[..len])
            .ok()
            .and_then(|packet| decode_nacks_from_compound(packet.payload).ok())
        else {
            return;
        };
        self.stats.nack_requests += nacks.len() as u64;
        if !nacks.is_empty() {
            self.last_nack_sequences = nacks;
        }
    }

    fn should_drop(&mut self, sequence: Option<u16>) -> bool {
        let Some(sequence) = sequence else {
            return false;
        };
        let extended = self.extend_media_sequence(sequence);
        if self.dropped_sequences.remove(&extended) {
            self.stats.recovered_forwards += 1;
            return false;
        }
        if let Some(highest) = self.highest_media_sequence {
            let forward_distance = extended.wrapping_sub(highest);
            if forward_distance == 0 || forward_distance >= 0x8000_0000 {
                return false;
            }
        }

        self.highest_media_sequence = Some(extended);
        self.stats.media_first_transmissions += 1;
        let drop =
            self.drop_every > 0 && self.stats.media_first_transmissions % self.drop_every == 0;
        if drop {
            self.expire_oldest_drop_if_full();
            self.dropped_sequences.insert(extended);
            self.dropped_sequence_order.push_back(extended);
            self.stats.injected_drops += 1;
        }
        drop
    }

    fn expire_oldest_drop_if_full(&mut self) {
        while self.dropped_sequence_order.len() >= MAX_TRACKED_DROPS {
            let Some(sequence) = self.dropped_sequence_order.pop_front() else {
                break;
            };
            if self.dropped_sequences.remove(&sequence) {
                self.stats.expired_drops += 1;
            }
        }
    }

    fn extend_media_sequence(&self, sequence: u16) -> u32 {
        self.highest_media_sequence
            .map_or(u32::from(sequence), |highest| {
                extend_near(highest, sequence)
            })
    }
}

fn media_sequence(datagram: &[u8]) -> Option<u16> {
    let reduced = ReducedPacket::decode(datagram).ok()?;
    let rtp = RtpPacket::decode(reduced.payload).ok()?;
    matches!(
        rtp.header.payload_type,
        RTP_PAYLOAD_TYPE_MPEGTS | RTP_PAYLOAD_TYPE_RIST
    )
    .then_some(rtp.header.sequence_number)
}

fn ensure_same_address_family(first: SocketAddr, second: SocketAddr) -> io::Result<()> {
    if first.is_ipv4() == second.is_ipv4() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loss proxy addresses must use one IP address family",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_core::packet::rtcp::NackMode;
    use rist_core::time::ntp_now;
    use rist_mio::{MainMioReceiver, MainMioSender};
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::thread;
    use std::time::{Duration, Instant};

    fn loopback_any() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn main_recovery_restores_every_injected_udp_loss() {
        const PACKETS: u16 = 21;
        const DROP_EVERY: u64 = 5;

        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "loss-proxy", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut proxy = LossProxy::bind(LossProxyConfig {
            listen: loopback_any(),
            upstream_bind: loopback_any(),
            target: receiver_addr,
            drop_every: DROP_EVERY,
        })
        .unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), proxy.listen_addr().unwrap(), flow_id, 256)
                .unwrap();

        for sequence in 0..PACKETS {
            let payload = vec![(sequence & 0xff) as u8; 1_316];
            sender
                .send_payload(&payload, ntp_now(), Instant::now())
                .unwrap();
            proxy.poll().unwrap();
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received = HashSet::new();
        let mut receiver_buffer = vec![0; 65_536];
        let mut feedback_buffer = vec![0; 65_536];
        while received.len() < usize::from(PACKETS) {
            proxy.poll().unwrap();
            while let Some((_from, payload)) =
                receiver.try_recv_payload(&mut receiver_buffer).unwrap()
            {
                assert_eq!(payload.payload.len(), 1_316);
                received.insert(payload.payload[0]);
            }
            receiver
                .poll_rtcp_and_send(Instant::now(), ntp_now())
                .unwrap();
            proxy.poll().unwrap();
            while sender
                .try_recv_feedback_and_retransmit(&mut feedback_buffer)
                .unwrap()
                .is_some()
            {}

            assert!(
                Instant::now() < deadline,
                "timed out after receiving {} of {PACKETS} payloads; proxy={:?}, last_nacks={:?}, receiver={:?}, sender={:?}",
                received.len(),
                proxy.stats(),
                proxy.last_nack_sequences(),
                receiver.stats(),
                sender.stats()
            );
            thread::sleep(Duration::from_millis(1));
        }

        let proxy_stats = proxy.stats();
        assert_eq!(proxy_stats.injected_drops, 4);
        assert_eq!(proxy_stats.recovered_forwards, 4);
        assert!(proxy_stats.all_injected_drops_recovered());
        assert_eq!(receiver.stats().recovered_packets, 4);
        assert_eq!(receiver.stats().currently_missing_packets, 0);
        assert_eq!(sender.stats().retransmitted_packets, 4);
    }
}
