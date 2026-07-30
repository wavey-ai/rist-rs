#![forbid(unsafe_code)]
//! Mio transport boundary for the pure Rust RIST implementation.
//!
//! This is intentionally small. The protocol state lives in `rist-core`; this
//! crate only owns nonblocking UDP readiness and datagram movement.
//! UDP send operations report `ENOBUFS` as `WouldBlock` so callers can use one
//! backpressure path.

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};
use rist_core::auth::{EapSrpAuthenticatorSession, EapSrpClientSession, EapolFrame, SrpUserRecord};
use rist_core::crypto::PskKey;
use rist_core::packet::gre::{
    BufferNegotiation, GreKeepalive, OwnedBufferNegotiationPacket, OwnedKeepalivePacket,
    OwnedOobPacket,
};
use rist_core::packet::rtp::{encode_packet, RtpHeader, RtpPacket};
use rist_core::time::ntp_now;
use rist_core::{
    packet::rtcp::NackMode, CongestionControlMode, MainControlPacket, MainOutboundPacket,
    MainPacket, MainReceiverCore, MainReceiverFeedback, MainSenderCore, MainSenderPeerState,
    MainSessionConfig, MainSessionPoll, MainSessionTimers, OutboundPacket, PeerSelection,
    ReceivedPayload, ReceiverStats, RecoveryConfig, SenderStats, SimpleReceiverCore,
    SimpleSenderCore, SrpCredentialStore, WeightedPeerSelector,
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Instant;

const PENDING_SEND_CAPACITY: usize = 256;
pub const DEFAULT_MAIN_EVENT_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_MAIN_PEER_CAPACITY: usize = 256;

struct PendingDatagram {
    bytes: Vec<u8>,
    peer: SocketAddr,
}

fn no_remote_peer_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "no remote RIST peer is available",
    )
}

pub struct RtpUdpSocket {
    socket: UdpSocket,
    peer: Option<SocketAddr>,
    next_sequence: u16,
    ssrc: u32,
}

impl RtpUdpSocket {
    pub fn bind(local: SocketAddr, ssrc: u32) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(local)?,
            peer: None,
            next_sequence: 0,
            ssrc,
        })
    }

    pub fn bind_reuse(local: SocketAddr, ssrc: u32) -> io::Result<Self> {
        Ok(Self {
            socket: bind_reuse_udp(local)?,
            peer: None,
            next_sequence: 0,
            ssrc,
        })
    }

    pub fn connect(local: SocketAddr, peer: SocketAddr, ssrc: u32) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.connect(peer)?;
        Ok(Self {
            socket,
            peer: Some(peer),
            next_sequence: 0,
            ssrc,
        })
    }

    pub fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.register(registry, token, interests)
    }

    pub fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.reregister(registry, token, interests)
    }

    pub fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.socket.deregister(registry)
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
        match self.peer {
            Some(_) => self.socket.send(packet).map_err(normalize_udp_send_error),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peer configured",
            )),
        }
    }

    pub fn send_packet_to(&mut self, peer: SocketAddr, packet: &[u8]) -> io::Result<usize> {
        self.socket
            .send_to(packet, peer)
            .map_err(normalize_udp_send_error)
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
    }

    pub fn set_multicast_if_v4(&self, interface: Ipv4Addr) -> io::Result<()> {
        SockRef::from(&self.socket).set_multicast_if_v4(&interface)
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(&multiaddr, &interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.leave_multicast_v4(&multiaddr, &interface)
    }

    pub fn send_mpegts_payload(&mut self, timestamp: u32, payload: &[u8]) -> io::Result<usize> {
        let header = RtpHeader::new_mpegts(self.next_sequence, timestamp, self.ssrc);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let packet = encode_packet(header, payload);
        self.send_packet(&packet)
    }

    pub fn send_mpegts_payload_to(
        &mut self,
        peer: SocketAddr,
        timestamp: u32,
        payload: &[u8],
    ) -> io::Result<usize> {
        let header = RtpHeader::new_mpegts(self.next_sequence, timestamp, self.ssrc);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let packet = encode_packet(header, payload);
        self.socket
            .send_to(&packet, peer)
            .map_err(normalize_udp_send_error)
    }

    pub fn recv_packet<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> io::Result<Option<(SocketAddr, RtpPacket<'a>)>> {
        let Some((from, data)) = self.recv_datagram(buf)? else {
            return Ok(None);
        };
        let packet = RtpPacket::decode(data)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Some((from, packet)))
    }

    pub fn recv_datagram<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> io::Result<Option<(SocketAddr, &'a [u8])>> {
        match self.socket.recv_from(buf) {
            Ok((len, from)) => Ok(Some((from, &buf[..len]))),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

fn simple_rtcp_addr(rtp: SocketAddr) -> io::Result<SocketAddr> {
    if rtp.port() % 2 != 0 || rtp.port() == u16::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Simple-profile RTP port must be even",
        ));
    }
    let mut rtcp = rtp;
    rtcp.set_port(rtp.port() + 1);
    Ok(rtcp)
}

fn simple_rtp_addr(rtcp: SocketAddr) -> io::Result<SocketAddr> {
    if rtcp.port() % 2 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Simple-profile RTCP port must be odd",
        ));
    }
    let mut rtp = rtcp;
    rtp.set_port(rtcp.port() - 1);
    Ok(rtp)
}

fn bind_simple_pair(
    local: SocketAddr,
    ssrc: u32,
    reuse: bool,
) -> io::Result<(RtpUdpSocket, RtpUdpSocket)> {
    let bind = |addr| {
        if reuse {
            RtpUdpSocket::bind_reuse(addr, ssrc)
        } else {
            RtpUdpSocket::bind(addr, ssrc)
        }
    };
    if local.port() != 0 {
        let rtcp_addr = simple_rtcp_addr(local)?;
        return Ok((bind(local)?, bind(rtcp_addr)?));
    }

    let mut last_error = None;
    for _ in 0..128 {
        let first = bind(local)?;
        let first_addr = first.local_addr()?;
        if first_addr.port() % 2 == 0 {
            match bind(simple_rtcp_addr(first_addr)?) {
                Ok(rtcp) => return Ok((first, rtcp)),
                Err(error) => last_error = Some(error),
            }
        } else {
            let mut rtp_addr = first_addr;
            rtp_addr.set_port(first_addr.port() - 1);
            match bind(rtp_addr) {
                Ok(rtp) => return Ok((rtp, first)),
                Err(error) => last_error = Some(error),
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "failed to allocate an adjacent Simple-profile port pair",
        )
    }))
}

fn normalize_udp_send_error(error: io::Error) -> io::Error {
    if is_udp_enobufs(&error) {
        io::Error::new(io::ErrorKind::WouldBlock, error)
    } else {
        error
    }
}

#[cfg(unix)]
fn is_udp_enobufs(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOBUFS)
}

#[cfg(not(unix))]
fn is_udp_enobufs(_error: &io::Error) -> bool {
    false
}

fn bind_reuse_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if local.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    let socket: StdUdpSocket = socket.into();
    Ok(UdpSocket::from_std(socket))
}

pub struct SimpleMioSender {
    rtp_socket: RtpUdpSocket,
    rtcp_socket: RtpUdpSocket,
    core: SimpleSenderCore,
    peer: Option<SocketAddr>,
    pending: VecDeque<PendingDatagram>,
    rtcp_pending: VecDeque<PendingDatagram>,
}

impl SimpleMioSender {
    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        ssrc: u32,
        history_packets: usize,
    ) -> io::Result<Self> {
        simple_rtcp_addr(peer)?;
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, ssrc, false)?;
        Ok(Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleSenderCore::new(ssrc, history_packets),
            peer: Some(peer),
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
            rtcp_pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
        })
    }

    pub fn listen(local: SocketAddr, ssrc: u32, history_packets: usize) -> io::Result<Self> {
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, ssrc, false)?;
        Ok(Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleSenderCore::new(ssrc, history_packets),
            peer: None,
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
            rtcp_pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
        })
    }

    pub fn build_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> OutboundPacket {
        self.core.send_payload(payload, ntp_timestamp, now)
    }

    pub fn build_payload_with_sequence(
        &mut self,
        sequence: u32,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> OutboundPacket {
        self.core
            .send_payload_with_sequence(sequence, payload, ntp_timestamp, now)
    }

    pub fn enable_null_packet_suppression(&mut self) {
        self.core.enable_null_packet_suppression();
    }

    pub fn disable_null_packet_suppression(&mut self) {
        self.core.disable_null_packet_suppression();
    }

    pub fn null_packet_suppression_enabled(&self) -> bool {
        self.core.null_packet_suppression_enabled()
    }

    pub fn set_next_sequence(&mut self, sequence: u32) {
        self.core.set_next_sequence(sequence);
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core.set_recovery_config(recovery, congestion_control);
    }

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn send_outbound(&mut self, packet: &OutboundPacket) -> io::Result<usize> {
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(packet.bytes.len())
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<OutboundPacket> {
        self.peer.ok_or_else(no_remote_peer_error)?;
        self.ensure_pending_capacity()?;
        let packet = self.build_payload(payload, ntp_timestamp, now);
        self.send_outbound(&packet)?;
        Ok(packet)
    }

    /// Retries queued datagrams in FIFO order. A `WouldBlock` condition keeps
    /// the exact encoded bytes at the head of the bounded queue.
    pub fn flush_pending(&mut self) -> io::Result<usize> {
        let mut sent = 0;
        while let Some(packet) = self.pending.front() {
            match self.rtp_socket.send_packet_to(packet.peer, &packet.bytes) {
                Ok(len) if len == packet.bytes.len() => {
                    self.pending.pop_front();
                    sent += 1;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP send accepted a partial datagram",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        while let Some(packet) = self.rtcp_pending.front() {
            match self.rtcp_socket.send_packet_to(packet.peer, &packet.bytes) {
                Ok(len) if len == packet.bytes.len() => {
                    self.rtcp_pending.pop_front();
                    sent += 1;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP send accepted a partial datagram",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }

    pub fn pending_send_len(&self) -> usize {
        self.pending.len() + self.rtcp_pending.len()
    }

    fn ensure_pending_capacity(&self) -> io::Result<()> {
        if self.pending.len() >= PENDING_SEND_CAPACITY {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RIST pending-send queue is full",
            ))
        } else {
            Ok(())
        }
    }

    fn enqueue_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.ensure_pending_capacity()?;
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.pending.push_back(PendingDatagram {
            bytes: packet.to_vec(),
            peer,
        });
        Ok(())
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.rtp_socket.set_multicast_loop_v4(on)?;
        self.rtcp_socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.rtp_socket.set_multicast_ttl_v4(ttl)?;
        self.rtcp_socket.set_multicast_ttl_v4(ttl)
    }

    pub fn set_multicast_if_v4(&self, interface: Ipv4Addr) -> io::Result<()> {
        self.rtp_socket.set_multicast_if_v4(interface)?;
        self.rtcp_socket.set_multicast_if_v4(interface)
    }

    pub fn send_rtcp(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.ensure_rtcp_pending_capacity()?;
        let peer = simple_rtcp_addr(self.peer.ok_or_else(no_remote_peer_error)?)?;
        self.rtcp_pending.push_back(PendingDatagram {
            bytes: packet.to_vec(),
            peer,
        });
        self.flush_pending()?;
        Ok(packet.len())
    }

    pub fn send_echo_request_at(&mut self, ntp_timestamp: u64) -> io::Result<usize> {
        let packet = self.core.build_echo_request(ntp_timestamp);
        self.send_rtcp(&packet)
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<usize>> {
        self.ensure_rtcp_pending_capacity()?;
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.send_rtcp(&packet).map(Some)
    }

    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let Some((from, feedback)) = self.rtcp_socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        self.handle_feedback_and_retransmit_from(from, feedback)
    }

    pub fn try_recv_feedback_and_retransmit_at(
        &mut self,
        buf: &mut [u8],
        now_ntp: u64,
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let Some((from, feedback)) = self.rtcp_socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        self.handle_feedback_and_retransmit_at_from(from, feedback, now_ntp)
            .map(Some)
    }

    fn handle_feedback_and_retransmit_from(
        &mut self,
        from: SocketAddr,
        feedback: &[u8],
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let rtp_peer = simple_rtp_addr(from)?;
        if self.peer.is_some_and(|peer| peer != rtp_peer) {
            return Ok(None);
        }
        let retries = self
            .core
            .handle_feedback(feedback)
            .map_err(core_to_io_error)?;
        self.peer = Some(rtp_peer);
        for retry in &retries {
            self.send_outbound(retry)?;
        }
        Ok(Some(retries))
    }

    fn handle_feedback_and_retransmit_at_from(
        &mut self,
        from: SocketAddr,
        feedback: &[u8],
        now_ntp: u64,
    ) -> io::Result<Vec<OutboundPacket>> {
        let rtp_peer = simple_rtp_addr(from)?;
        if self.peer.is_some_and(|peer| peer != rtp_peer) {
            return Ok(Vec::new());
        }
        let retries = self
            .core
            .handle_feedback_at(feedback, now_ntp)
            .map_err(core_to_io_error)?;
        self.peer = Some(rtp_peer);
        for retry in &retries {
            self.send_outbound(retry)?;
        }
        Ok(retries)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.rtp_socket.local_addr()
    }

    pub fn rtcp_local_addr(&self) -> io::Result<SocketAddr> {
        self.rtcp_socket.local_addr()
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.rtp_socket.join_multicast_v4(multiaddr, interface)?;
        self.rtcp_socket.join_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.rtp_socket.leave_multicast_v4(multiaddr, interface)?;
        self.rtcp_socket.leave_multicast_v4(multiaddr, interface)
    }

    fn ensure_rtcp_pending_capacity(&self) -> io::Result<()> {
        if self.rtcp_pending.len() >= PENDING_SEND_CAPACITY {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RIST RTCP pending-send queue is full",
            ))
        } else {
            Ok(())
        }
    }
}

pub struct SimpleMioReceiver {
    rtp_socket: RtpUdpSocket,
    rtcp_socket: RtpUdpSocket,
    core: SimpleReceiverCore,
    last_rtp_peer: Option<SocketAddr>,
    last_rtcp_peer: Option<SocketAddr>,
    configured_peer: Option<SocketAddr>,
}

impl SimpleMioReceiver {
    pub fn bind(
        local: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, flow_id, false)?;
        Ok(Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleReceiverCore::new(flow_id, cname, nack_mode),
            last_rtp_peer: None,
            last_rtcp_peer: None,
            configured_peer: None,
        })
    }

    pub fn bind_reuse(
        local: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, flow_id, true)?;
        Ok(Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleReceiverCore::new(flow_id, cname, nack_mode),
            last_rtp_peer: None,
            last_rtcp_peer: None,
            configured_peer: None,
        })
    }

    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        let rtcp_peer = simple_rtcp_addr(peer)?;
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, flow_id, false)?;
        Ok(Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleReceiverCore::new(flow_id, cname, nack_mode),
            last_rtp_peer: Some(peer),
            last_rtcp_peer: Some(rtcp_peer),
            configured_peer: Some(peer),
        })
    }

    pub fn try_recv_payload(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, ReceivedPayload)>> {
        let Some((from, packet)) = self.rtp_socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if self.configured_peer.is_some_and(|peer| peer != from) {
            return Ok(None);
        }
        let payload = self.core.accept_packet(packet).map_err(core_to_io_error)?;
        self.last_rtp_peer = Some(from);
        Ok(Some((from, payload)))
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core.set_recovery_config(recovery, congestion_control);
    }

    pub fn feedback_packet(&mut self) -> Vec<u8> {
        self.core.build_feedback_and_record()
    }

    pub fn poll_rtcp_packet(&mut self, now: Instant, now_ntp: u64) -> Option<Vec<u8>> {
        self.core.poll_rtcp(now, now_ntp)
    }

    pub fn poll_rtcp_and_send(&mut self, now: Instant, now_ntp: u64) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_rtcp_peer else {
            return Ok(None);
        };
        let Some(packet) = self.poll_rtcp_packet(now, now_ntp) else {
            return Ok(None);
        };
        self.rtcp_socket.send_packet_to(peer, &packet).map(Some)
    }

    pub fn send_feedback(&mut self) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_rtcp_peer else {
            return Ok(None);
        };
        let feedback = self.feedback_packet();
        self.rtcp_socket.send_packet_to(peer, &feedback).map(Some)
    }

    pub fn send_feedback_to(&mut self, peer: SocketAddr) -> io::Result<usize> {
        let feedback = self.feedback_packet();
        let rtcp_peer = simple_rtcp_addr(peer)?;
        self.rtcp_socket.send_packet_to(rtcp_peer, &feedback)
    }

    pub fn try_recv_rtcp_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let Some((from, packet)) = self.rtcp_socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if self
            .configured_peer
            .and_then(|peer| simple_rtcp_addr(peer).ok())
            .is_some_and(|peer| peer != from)
        {
            return Ok(None);
        }
        let responses = self.core.handle_rtcp(packet).map_err(core_to_io_error)?;
        for response in &responses {
            self.rtcp_socket.send_packet_to(from, response)?;
        }
        self.last_rtcp_peer = Some(from);
        Ok(Some(responses.len()))
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.core.missing_sequences()
    }

    pub fn stats(&self) -> ReceiverStats {
        self.core.stats()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.rtp_socket.local_addr()
    }

    pub fn rtcp_local_addr(&self) -> io::Result<SocketAddr> {
        self.rtcp_socket.local_addr()
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.configured_peer.or(self.last_rtp_peer)
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.rtp_socket.join_multicast_v4(multiaddr, interface)?;
        self.rtcp_socket.join_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.rtp_socket.leave_multicast_v4(multiaddr, interface)?;
        self.rtcp_socket.leave_multicast_v4(multiaddr, interface)
    }
}

pub struct MainMioSender {
    socket: RtpUdpSocket,
    core: MainSenderCore,
    timers: MainSessionTimers,
    srp: Option<EapSrpClientSession>,
    srp_authenticator: Option<EapSrpAuthenticatorSession>,
    srp_candidates: HashMap<SocketAddr, EapSrpAuthenticatorSession>,
    peer: Option<SocketAddr>,
    listening: bool,
    last_reauthentication: Option<Instant>,
    pending: VecDeque<PendingDatagram>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainMioSessionPoll {
    pub poll: MainSessionPoll,
    pub keepalive: Option<MainControlPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainSenderEvent {
    Feedback {
        from: SocketAddr,
        retries: Vec<MainOutboundPacket>,
    },
    Eapol {
        from: SocketAddr,
        frame: EapolFrame,
    },
    Keepalive {
        from: SocketAddr,
        packet: OwnedKeepalivePacket,
    },
    BufferNegotiation {
        from: SocketAddr,
        packet: OwnedBufferNegotiationPacket,
    },
    Oob {
        from: SocketAddr,
        packet: OwnedOobPacket,
    },
    Unhandled {
        from: SocketAddr,
        packet: MainPacket,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainReceiverEvent {
    Payload {
        from: SocketAddr,
        payload: ReceivedPayload,
    },
    Rtcp {
        from: SocketAddr,
        responses: Vec<MainReceiverFeedback>,
    },
    Eapol {
        from: SocketAddr,
        frame: EapolFrame,
    },
    Keepalive {
        from: SocketAddr,
        packet: OwnedKeepalivePacket,
    },
    BufferNegotiation {
        from: SocketAddr,
        packet: OwnedBufferNegotiationPacket,
    },
    Oob {
        from: SocketAddr,
        packet: OwnedOobPacket,
    },
    Unhandled {
        from: SocketAddr,
        packet: MainPacket,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainEventQueue {
    Data,
    Rtcp,
    Eapol,
    Keepalive,
    BufferNegotiation,
    Oob,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainEventQueueCapacities {
    pub data: usize,
    pub rtcp: usize,
    pub eapol: usize,
    pub keepalive: usize,
    pub buffer_negotiation: usize,
    pub oob: usize,
    pub unknown: usize,
}

impl MainEventQueueCapacities {
    pub const fn uniform(capacity: usize) -> Self {
        Self {
            data: capacity,
            rtcp: capacity,
            eapol: capacity,
            keepalive: capacity,
            buffer_negotiation: capacity,
            oob: capacity,
            unknown: capacity,
        }
    }
}

impl Default for MainEventQueueCapacities {
    fn default() -> Self {
        Self::uniform(DEFAULT_MAIN_EVENT_QUEUE_CAPACITY)
    }
}

pub trait MainDispatchEvent {
    fn event_queue(&self) -> MainEventQueue;
}

impl MainDispatchEvent for MainSenderEvent {
    fn event_queue(&self) -> MainEventQueue {
        match self {
            Self::Feedback { .. } => MainEventQueue::Rtcp,
            Self::Eapol { .. } => MainEventQueue::Eapol,
            Self::Keepalive { .. } => MainEventQueue::Keepalive,
            Self::BufferNegotiation { .. } => MainEventQueue::BufferNegotiation,
            Self::Oob { .. } => MainEventQueue::Oob,
            Self::Unhandled { .. } => MainEventQueue::Unknown,
        }
    }
}

impl MainDispatchEvent for MainReceiverEvent {
    fn event_queue(&self) -> MainEventQueue {
        match self {
            Self::Payload { .. } => MainEventQueue::Data,
            Self::Rtcp { .. } => MainEventQueue::Rtcp,
            Self::Eapol { .. } => MainEventQueue::Eapol,
            Self::Keepalive { .. } => MainEventQueue::Keepalive,
            Self::BufferNegotiation { .. } => MainEventQueue::BufferNegotiation,
            Self::Oob { .. } => MainEventQueue::Oob,
            Self::Unhandled { .. } => MainEventQueue::Unknown,
        }
    }
}

#[derive(Debug)]
struct BoundedEventQueue<E> {
    events: VecDeque<E>,
    capacity: usize,
    dropped: u64,
}

impl<E> BoundedEventQueue<E> {
    fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }
}

#[derive(Debug)]
pub struct MainEventQueues<E> {
    data: BoundedEventQueue<E>,
    rtcp: BoundedEventQueue<E>,
    eapol: BoundedEventQueue<E>,
    keepalive: BoundedEventQueue<E>,
    buffer_negotiation: BoundedEventQueue<E>,
    oob: BoundedEventQueue<E>,
    unknown: BoundedEventQueue<E>,
}

#[derive(Debug)]
pub struct MainEventQueueFull<E> {
    pub queue: MainEventQueue,
    pub capacity: usize,
    pub event: E,
}

pub type MainSenderEventQueues = MainEventQueues<MainSenderEvent>;
pub type MainReceiverEventQueues = MainEventQueues<MainReceiverEvent>;

impl<E> MainEventQueues<E> {
    pub fn new(capacity: usize) -> Self {
        Self::with_capacities(MainEventQueueCapacities::uniform(capacity))
    }

    pub fn with_capacities(capacities: MainEventQueueCapacities) -> Self {
        Self {
            data: BoundedEventQueue::new(capacities.data),
            rtcp: BoundedEventQueue::new(capacities.rtcp),
            eapol: BoundedEventQueue::new(capacities.eapol),
            keepalive: BoundedEventQueue::new(capacities.keepalive),
            buffer_negotiation: BoundedEventQueue::new(capacities.buffer_negotiation),
            oob: BoundedEventQueue::new(capacities.oob),
            unknown: BoundedEventQueue::new(capacities.unknown),
        }
    }

    pub fn pop(&mut self, queue: MainEventQueue) -> Option<E> {
        self.queue_mut(queue).events.pop_front()
    }

    pub fn len(&self, queue: MainEventQueue) -> usize {
        self.queue(queue).events.len()
    }

    pub fn capacity(&self, queue: MainEventQueue) -> usize {
        self.queue(queue).capacity
    }

    pub fn dropped(&self, queue: MainEventQueue) -> u64 {
        self.queue(queue).dropped
    }

    pub fn is_empty(&self) -> bool {
        self.data.events.is_empty()
            && self.rtcp.events.is_empty()
            && self.eapol.events.is_empty()
            && self.keepalive.events.is_empty()
            && self.buffer_negotiation.events.is_empty()
            && self.oob.events.is_empty()
            && self.unknown.events.is_empty()
    }

    fn queue(&self, queue: MainEventQueue) -> &BoundedEventQueue<E> {
        match queue {
            MainEventQueue::Data => &self.data,
            MainEventQueue::Rtcp => &self.rtcp,
            MainEventQueue::Eapol => &self.eapol,
            MainEventQueue::Keepalive => &self.keepalive,
            MainEventQueue::BufferNegotiation => &self.buffer_negotiation,
            MainEventQueue::Oob => &self.oob,
            MainEventQueue::Unknown => &self.unknown,
        }
    }

    fn queue_mut(&mut self, queue: MainEventQueue) -> &mut BoundedEventQueue<E> {
        match queue {
            MainEventQueue::Data => &mut self.data,
            MainEventQueue::Rtcp => &mut self.rtcp,
            MainEventQueue::Eapol => &mut self.eapol,
            MainEventQueue::Keepalive => &mut self.keepalive,
            MainEventQueue::BufferNegotiation => &mut self.buffer_negotiation,
            MainEventQueue::Oob => &mut self.oob,
            MainEventQueue::Unknown => &mut self.unknown,
        }
    }
}

impl<E: MainDispatchEvent> MainEventQueues<E> {
    pub fn push(&mut self, event: E) -> Result<MainEventQueue, MainEventQueueFull<E>> {
        let queue = event.event_queue();
        let target = self.queue_mut(queue);
        if target.events.len() >= target.capacity {
            target.dropped = target.dropped.saturating_add(1);
            return Err(MainEventQueueFull {
                queue,
                capacity: target.capacity,
                event,
            });
        }
        target.events.push_back(event);
        Ok(queue)
    }
}

impl<E> Default for MainEventQueues<E> {
    fn default() -> Self {
        Self::with_capacities(MainEventQueueCapacities::default())
    }
}

impl MainMioSender {
    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        flow_id: u32,
        history_packets: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: MainSenderCore::new(flow_id, history_packets),
            timers: MainSessionTimers::new(),
            srp: None,
            srp_authenticator: None,
            srp_candidates: HashMap::new(),
            peer: Some(peer),
            listening: false,
            last_reauthentication: None,
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
        })
    }

    pub fn listen(local: SocketAddr, flow_id: u32, history_packets: usize) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: MainSenderCore::new(flow_id, history_packets),
            timers: MainSessionTimers::new(),
            srp: None,
            srp_authenticator: None,
            srp_candidates: HashMap::new(),
            peer: None,
            listening: true,
            last_reauthentication: None,
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
        })
    }

    pub fn build_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> MainOutboundPacket {
        self.core.send_payload(payload, ntp_timestamp, now)
    }

    pub fn enable_null_packet_suppression(&mut self) {
        self.core.enable_null_packet_suppression();
    }

    pub fn disable_null_packet_suppression(&mut self) {
        self.core.disable_null_packet_suppression();
    }

    pub fn null_packet_suppression_enabled(&self) -> bool {
        self.core.null_packet_suppression_enabled()
    }

    pub fn set_next_rtp_sequence(&mut self, sequence: u32) {
        self.core.set_next_rtp_sequence(sequence);
    }

    pub fn set_ports(&mut self, virt_src_port: u16, virt_dst_port: u16) {
        self.core.set_ports(virt_src_port, virt_dst_port);
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core.set_recovery_config(recovery, congestion_control);
    }

    pub fn session_config(&self) -> MainSessionConfig {
        self.timers.config()
    }

    pub fn set_session_config(&mut self, config: MainSessionConfig) {
        self.timers.set_config(config);
        self.last_reauthentication = None;
    }

    pub fn observe_peer_activity(&mut self, now: Instant) {
        self.timers.observe_peer_activity(now);
    }

    pub fn poll_session(&mut self, now: Instant) -> MainSessionPoll {
        self.timers.poll(now)
    }

    pub fn poll_session_and_send_keepalive(
        &mut self,
        now: Instant,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainMioSessionPoll> {
        let poll = self.poll_session(now);
        if poll.timed_out && self.reauthentication_due(now) {
            self.start_srp_authentication()?;
            self.last_reauthentication = Some(now);
        }
        let keepalive = if poll.keepalive_due {
            Some(self.send_keepalive(keepalive)?)
        } else {
            None
        };
        Ok(MainMioSessionPoll { poll, keepalive })
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.core.set_tx_key(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
        self.core.set_rx_key(key);
    }

    pub fn enable_srp_client(&mut self, username: impl Into<String>, password: impl AsRef<[u8]>) {
        self.srp =
            Some(EapSrpClientSession::new(username, password).with_session_key_passphrase(false));
        self.srp_authenticator = None;
        self.srp_candidates.clear();
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> io::Result<()> {
        let Some(session) = &mut self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        session.set_password(password);
        self.last_reauthentication = None;
        Ok(())
    }

    pub fn set_srp_client_session(&mut self, session: EapSrpClientSession) {
        self.srp = Some(session);
        self.srp_authenticator = None;
        self.srp_candidates.clear();
        self.last_reauthentication = None;
    }

    pub fn enable_srp_authenticator(&mut self, store: SrpCredentialStore) {
        self.set_srp_authenticator_session(
            EapSrpAuthenticatorSession::new(store).with_session_key_passphrase(false),
        );
    }

    pub fn set_srp_authenticator_session(&mut self, session: EapSrpAuthenticatorSession) {
        self.srp = None;
        self.srp_authenticator = Some(session);
        self.srp_candidates.clear();
    }

    pub fn stage_srp_password(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> io::Result<SrpUserRecord> {
        let Some(session) = &mut self.srp_authenticator else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP authenticator session is not configured",
            ));
        };
        let record = session
            .stage_password(username, password)
            .map_err(core_to_io_error)?;
        self.srp_candidates.clear();
        Ok(record)
    }

    pub fn srp_authenticated(&self) -> bool {
        if let Some(session) = &self.srp {
            return session.authenticated();
        }
        if self.srp_authenticator.is_some() {
            return self
                .peer
                .and_then(|peer| self.srp_candidates.get(&peer))
                .is_some_and(EapSrpAuthenticatorSession::authenticated);
        }
        true
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn send_outbound(&mut self, packet: &MainOutboundPacket) -> io::Result<usize> {
        self.ensure_srp_authenticated()?;
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(packet.bytes.len())
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<MainOutboundPacket> {
        self.ensure_peer_available()?;
        self.ensure_srp_authenticated()?;
        self.ensure_pending_capacity()?;
        let packet = self.build_payload(payload, ntp_timestamp, now);
        self.send_outbound(&packet)?;
        Ok(packet)
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<MainControlPacket>> {
        self.ensure_peer_available()?;
        self.ensure_srp_authenticated()?;
        self.ensure_pending_capacity()?;
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(Some(packet))
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        self.core.build_keepalive(keepalive)
    }

    pub fn send_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> io::Result<MainControlPacket> {
        self.ensure_peer_available()?;
        self.ensure_pending_capacity()?;
        let packet = self.build_keepalive(keepalive);
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(packet)
    }

    pub fn build_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> MainControlPacket {
        self.core.build_buffer_negotiation(negotiation)
    }

    pub fn send_buffer_negotiation(
        &mut self,
        negotiation: BufferNegotiation<'_>,
    ) -> io::Result<MainControlPacket> {
        self.ensure_peer_available()?;
        self.ensure_pending_capacity()?;
        let packet = self.build_buffer_negotiation(negotiation);
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(packet)
    }

    pub fn start_srp_authentication(&mut self) -> io::Result<MainControlPacket> {
        self.ensure_peer_available()?;
        let Some(session) = &mut self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        let frame = session.start();
        self.last_reauthentication = Some(Instant::now());
        self.send_eapol_frame(&frame)
    }

    pub fn send_eapol_frame(&mut self, frame: &EapolFrame) -> io::Result<MainControlPacket> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.send_eapol_frame_to(peer, frame)
    }

    fn send_eapol_frame_to(
        &mut self,
        peer: SocketAddr,
        frame: &EapolFrame,
    ) -> io::Result<MainControlPacket> {
        self.ensure_pending_capacity()?;
        let packet = self.core.build_eapol(frame).map_err(core_to_io_error)?;
        self.enqueue_packet_to(peer, &packet.bytes)?;
        self.flush_pending()?;
        Ok(packet)
    }

    pub fn send_oob(&mut self, payload: &[u8]) -> io::Result<MainControlPacket> {
        self.ensure_peer_available()?;
        self.ensure_srp_authenticated()?;
        self.ensure_pending_capacity()?;
        let packet = self.core.build_oob(payload);
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(packet)
    }

    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<MainSenderEvent>> {
        let Some((from, datagram)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        let packet = self
            .core
            .decode_datagram(datagram)
            .map_err(core_to_io_error)?;
        if self.peer.is_some_and(|peer| peer != from) {
            return Ok(Some(MainSenderEvent::Unhandled { from, packet }));
        }
        let event = match packet {
            MainPacket::Eapol(eapol) => {
                if self.handle_eapol_frame_from(from, &eapol.frame)? {
                    self.timers.observe_peer_activity(Instant::now());
                }
                if self.srp_authenticated() {
                    self.last_reauthentication = None;
                }
                MainSenderEvent::Eapol {
                    from,
                    frame: eapol.frame,
                }
            }
            packet if !self.srp_authenticated() => {
                return Ok(Some(MainSenderEvent::Unhandled { from, packet }));
            }
            MainPacket::Reduced(packet) if looks_like_rtcp(&packet.payload) => {
                let retries = self
                    .core
                    .handle_reduced_feedback(packet.reduced, &packet.payload)
                    .map_err(core_to_io_error)?;
                self.select_unsecured_listener_peer(from);
                for retry in &retries {
                    self.send_outbound(retry)?;
                }
                self.timers.observe_peer_activity(Instant::now());
                MainSenderEvent::Feedback { from, retries }
            }
            MainPacket::Keepalive(packet) => {
                let discovered = self.listening && self.peer.is_none();
                self.select_unsecured_listener_peer(from);
                if self.listening && self.peer == Some(from) {
                    self.core.upgrade_gre_version(packet.gre.version);
                }
                if discovered && self.peer == Some(from) {
                    self.send_keepalive(GreKeepalive::librist_default([0; 6]))?;
                }
                self.timers.observe_peer_activity(Instant::now());
                MainSenderEvent::Keepalive { from, packet }
            }
            MainPacket::BufferNegotiation(packet) => {
                self.select_unsecured_listener_peer(from);
                self.timers.observe_peer_activity(Instant::now());
                MainSenderEvent::BufferNegotiation { from, packet }
            }
            MainPacket::Oob(packet) => {
                self.select_unsecured_listener_peer(from);
                self.timers.observe_peer_activity(Instant::now());
                MainSenderEvent::Oob { from, packet }
            }
            packet => MainSenderEvent::Unhandled { from, packet },
        };
        Ok(Some(event))
    }

    pub fn try_recv_and_dispatch(
        &mut self,
        buf: &mut [u8],
        queues: &mut MainSenderEventQueues,
    ) -> io::Result<Option<MainEventQueue>> {
        let Some(event) = self.try_recv_event(buf)? else {
            return Ok(None);
        };
        queues.push(event).map(Some).map_err(queue_full_to_io)
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<EapolFrame>> {
        match self.try_recv_event(buf)? {
            Some(MainSenderEvent::Eapol { frame, .. }) => Ok(Some(frame)),
            _ => Ok(None),
        }
    }

    pub fn try_recv_keepalive(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedKeepalivePacket)>> {
        match self.try_recv_event(buf)? {
            Some(MainSenderEvent::Keepalive { from, packet }) => Ok(Some((from, packet))),
            _ => Ok(None),
        }
    }

    pub fn try_recv_buffer_negotiation(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedBufferNegotiationPacket)>> {
        match self.try_recv_event(buf)? {
            Some(MainSenderEvent::BufferNegotiation { from, packet }) => Ok(Some((from, packet))),
            _ => Ok(None),
        }
    }

    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<MainOutboundPacket>>> {
        match self.try_recv_event(buf)? {
            Some(MainSenderEvent::Feedback { retries, .. }) => Ok(Some(retries)),
            _ => Ok(None),
        }
    }

    pub fn flush_pending(&mut self) -> io::Result<usize> {
        let mut sent = 0;
        while let Some(packet) = self.pending.front() {
            match self.socket.send_packet_to(packet.peer, &packet.bytes) {
                Ok(len) if len == packet.bytes.len() => {
                    self.pending.pop_front();
                    sent += 1;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP send accepted a partial datagram",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }

    pub fn pending_send_len(&self) -> usize {
        self.pending.len()
    }

    fn ensure_pending_capacity(&self) -> io::Result<()> {
        if self.pending.len() >= PENDING_SEND_CAPACITY {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RIST pending-send queue is full",
            ))
        } else {
            Ok(())
        }
    }

    fn enqueue_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.enqueue_packet_to(peer, packet)
    }

    fn enqueue_packet_to(&mut self, peer: SocketAddr, packet: &[u8]) -> io::Result<()> {
        self.ensure_pending_capacity()?;
        self.pending.push_back(PendingDatagram {
            bytes: packet.to_vec(),
            peer,
        });
        Ok(())
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
    }

    pub fn set_multicast_if_v4(&self, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.set_multicast_if_v4(interface)
    }

    fn handle_eapol_frame_from(
        &mut self,
        from: SocketAddr,
        frame: &EapolFrame,
    ) -> io::Result<bool> {
        if let Some(session) = &mut self.srp {
            let authenticated = session.authenticated();
            let (response, accepted) = match session.handle_frame(frame) {
                Ok(response) => (response, true),
                Err(rist_core::Error::InvalidEapPacket) if authenticated => (None, false),
                Err(err) => return Err(core_to_io_error(err)),
            };
            if let Some(response) = response {
                self.send_eapol_frame_to(from, &response)?;
            }
            return Ok(accepted);
        }

        let Some(template) = &self.srp_authenticator else {
            return Ok(false);
        };
        if !self.srp_candidates.contains_key(&from)
            && self.srp_candidates.len() >= DEFAULT_MAIN_PEER_CAPACITY
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Main sender SRP candidate capacity is full",
            ));
        }
        let template = template.clone();
        let session = self.srp_candidates.entry(from).or_insert_with(|| template);
        let authenticated = session.authenticated();
        let (response, accepted) = match session.handle_frame(frame) {
            Ok(response) => (response, true),
            Err(rist_core::Error::InvalidEapPacket) if authenticated => (None, false),
            Err(err) => return Err(core_to_io_error(err)),
        };
        let completed = session.authenticated();
        if let Some(response) = response {
            self.send_eapol_frame_to(from, &response)?;
        }
        if completed && self.peer.is_none() {
            self.peer = Some(from);
        }
        Ok(accepted)
    }

    fn select_unsecured_listener_peer(&mut self, from: SocketAddr) {
        if self.listening && self.peer.is_none() && self.srp_authenticator.is_none() {
            self.peer = Some(from);
        }
    }

    fn ensure_srp_authenticated(&self) -> io::Result<()> {
        if self.srp_authenticated() {
            Ok(())
        } else {
            Err(srp_not_authenticated_error())
        }
    }

    fn ensure_peer_available(&self) -> io::Result<()> {
        self.peer.map(|_| ()).ok_or_else(no_remote_peer_error)
    }

    fn reauthentication_due(&self, now: Instant) -> bool {
        if self.srp.is_none() || self.listening {
            return false;
        }
        let Some(last_activity) = self.timers.last_peer_activity() else {
            return false;
        };
        let config = self.timers.config();
        let minimum_silence = config
            .session_timeout
            .max(config.keepalive_interval.saturating_mul(4));
        if now.saturating_duration_since(last_activity) <= minimum_silence {
            return false;
        }
        self.last_reauthentication.map_or(true, |last| {
            now.saturating_duration_since(last) >= config.session_timeout
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainMioPeer {
    pub addr: SocketAddr,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainMioMultiSend {
    pub peers: Vec<usize>,
    pub peer_packets: Vec<MainMioPeerPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainMioPeerPacket {
    pub peer: usize,
    pub packet: MainOutboundPacket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainMioPeerControlPacket {
    pub peer: usize,
    pub packet: MainControlPacket,
}

pub struct MainMioMultiSender {
    socket: RtpUdpSocket,
    core: MainSenderCore,
    session_config: MainSessionConfig,
    srp: Option<EapSrpClientSession>,
    peers: Vec<MainMioPeer>,
    peer_runtime: Vec<MainMultiSenderPeerRuntime>,
    selector: WeightedPeerSelector,
    pending: VecDeque<PendingMultiDatagram>,
}

struct MainMultiSenderPeerRuntime {
    sender: MainSenderPeerState,
    timers: MainSessionTimers,
    srp: Option<EapSrpClientSession>,
    last_reauthentication: Option<Instant>,
}

struct PendingMultiDatagram {
    bytes: Vec<u8>,
    destinations: Vec<SocketAddr>,
    next_destination: usize,
}

impl MainMioMultiSender {
    pub fn bind(local: SocketAddr, flow_id: u32, history_packets: usize) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: MainSenderCore::new(flow_id, history_packets),
            session_config: MainSessionConfig::default(),
            srp: None,
            peers: Vec::new(),
            peer_runtime: Vec::new(),
            selector: WeightedPeerSelector::new(),
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
        })
    }

    pub fn add_peer(&mut self, peer: SocketAddr, weight: u32) -> usize {
        let index = self.peers.len();
        self.peers.push(MainMioPeer { addr: peer, weight });
        self.peer_runtime.push(MainMultiSenderPeerRuntime {
            sender: self.core.new_peer_state(),
            timers: MainSessionTimers::with_config(self.session_config),
            srp: self.srp.clone(),
            last_reauthentication: None,
        });
        self.selector.add_peer(weight);
        index
    }

    pub fn peers(&self) -> &[MainMioPeer] {
        &self.peers
    }

    pub fn set_peer_weight(&mut self, index: usize, weight: u32) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        peer.weight = weight;
        self.selector.set_weight(index, weight)
    }

    pub fn build_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> MainOutboundPacket {
        self.core.send_payload(payload, ntp_timestamp, now)
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<MainMioMultiSend> {
        let peers = self.select_peers()?;
        self.ensure_peers_authenticated(&peers)?;
        self.ensure_pending_capacity_for(peers.len())?;
        let packet = self.core.prepare_payload(payload, ntp_timestamp, now);
        let mut peer_packets = Vec::with_capacity(peers.len());
        for &peer in &peers {
            let packet = self
                .core
                .wrap_payload_for_peer(&mut self.peer_runtime[peer].sender, &packet);
            self.enqueue_datagram(&packet.bytes, vec![self.peers[peer].addr])?;
            peer_packets.push(MainMioPeerPacket { peer, packet });
        }
        self.flush_pending()?;
        Ok(MainMioMultiSend {
            peers,
            peer_packets,
        })
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<(MainControlPacket, Vec<usize>)>> {
        self.ensure_all_peers_authenticated()?;
        let Some(payload) = self.core.poll_rtcp_payload(now, ntp_timestamp) else {
            return Ok(None);
        };
        let peers = self.select_peers()?;
        self.ensure_peers_authenticated(&peers)?;
        self.ensure_pending_capacity_for(peers.len())?;
        let mut first_packet = None;
        for &peer in &peers {
            let packet = self
                .core
                .wrap_control_for_peer(&mut self.peer_runtime[peer].sender, &payload);
            self.enqueue_datagram(&packet.bytes, vec![self.peers[peer].addr])?;
            first_packet.get_or_insert(packet);
        }
        self.flush_pending()?;
        Ok(first_packet.map(|packet| (packet, peers)))
    }

    pub fn poll_session(&mut self, now: Instant) -> MainSessionPoll {
        let polls = self
            .peer_runtime
            .iter_mut()
            .map(|runtime| runtime.timers.poll(now))
            .collect::<Vec<_>>();
        MainSessionPoll {
            keepalive_due: polls.iter().any(|poll| poll.keepalive_due),
            timed_out: polls.iter().any(|poll| poll.timed_out),
        }
    }

    pub fn poll_peer_session(&mut self, peer: usize, now: Instant) -> Option<MainSessionPoll> {
        Some(self.peer_runtime.get_mut(peer)?.timers.poll(now))
    }

    pub fn set_session_config(&mut self, config: MainSessionConfig) {
        self.session_config = config;
        for runtime in &mut self.peer_runtime {
            runtime.timers.set_config(config);
            runtime.last_reauthentication = None;
        }
    }

    pub fn poll_session_and_send_keepalive(
        &mut self,
        now: Instant,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainMioSessionPoll> {
        let poll = self.poll_session(now);
        let reauthentication_peers = self
            .peer_runtime
            .iter()
            .enumerate()
            .filter_map(|(peer, runtime)| {
                (runtime.timers.is_timed_out(now) && multi_reauthentication_due(runtime, now))
                    .then_some(peer)
            })
            .collect::<Vec<_>>();
        for peer in reauthentication_peers {
            self.start_srp_authentication(peer)?;
        }
        let keepalive = if poll.keepalive_due {
            Some(self.send_keepalive_to_all(keepalive)?)
        } else {
            None
        };
        Ok(MainMioSessionPoll { poll, keepalive })
    }

    pub fn send_keepalive_to_all(
        &mut self,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainControlPacket> {
        if self.peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peers configured",
            ));
        }
        self.ensure_pending_capacity_for(self.peers.len())?;
        let mut first_packet = None;
        for peer in 0..self.peers.len() {
            let packet = self
                .core
                .build_keepalive_for_peer(&mut self.peer_runtime[peer].sender, keepalive);
            self.enqueue_datagram(&packet.bytes, vec![self.peers[peer].addr])?;
            first_packet.get_or_insert(packet);
        }
        self.flush_pending()?;
        Ok(first_packet.expect("at least one peer was checked"))
    }

    pub fn set_ports(&mut self, virt_src_port: u16, virt_dst_port: u16) {
        self.core.set_ports(virt_src_port, virt_dst_port);
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core.set_recovery_config(recovery, congestion_control);
    }

    pub fn set_next_rtp_sequence(&mut self, sequence: u32) {
        self.core.set_next_rtp_sequence(sequence);
    }

    pub fn enable_null_packet_suppression(&mut self) {
        self.core.enable_null_packet_suppression();
    }

    pub fn disable_null_packet_suppression(&mut self) {
        self.core.disable_null_packet_suppression();
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        for runtime in &mut self.peer_runtime {
            runtime.sender.set_tx_key(key.clone());
        }
        self.core.set_tx_key(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
        for runtime in &mut self.peer_runtime {
            runtime.sender.set_rx_key(key.clone());
        }
        self.core.set_rx_key(key);
    }

    pub fn enable_srp_client(&mut self, username: impl Into<String>, password: impl AsRef<[u8]>) {
        self.set_srp_client_session(
            EapSrpClientSession::new(username, password).with_session_key_passphrase(false),
        );
    }

    pub fn set_srp_client_session(&mut self, session: EapSrpClientSession) {
        self.srp = Some(session.clone());
        for runtime in &mut self.peer_runtime {
            runtime.srp = Some(session.clone());
            runtime.last_reauthentication = None;
        }
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> io::Result<()> {
        let Some(session) = &mut self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        session.set_password(password.as_ref());
        for runtime in &mut self.peer_runtime {
            if let Some(session) = &mut runtime.srp {
                session.set_password(password.as_ref());
            }
        }
        Ok(())
    }

    pub fn peer_srp_authenticated(&self, peer: usize) -> Option<bool> {
        Some(peer_authenticated(self.peer_runtime.get(peer)?))
    }

    pub fn srp_authenticated(&self) -> bool {
        self.peer_runtime.iter().all(peer_authenticated)
    }

    pub fn start_srp_authentication(&mut self, peer: usize) -> io::Result<MainControlPacket> {
        let Some(runtime) = self.peer_runtime.get_mut(peer) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RIST peer index is not configured",
            ));
        };
        let Some(session) = &mut runtime.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        let frame = session.start();
        runtime.last_reauthentication = Some(Instant::now());
        self.send_eapol_frame_to(peer, &frame)
    }

    pub fn start_srp_authentication_all(&mut self) -> io::Result<Vec<MainMioPeerControlPacket>> {
        if self.peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peers configured",
            ));
        }
        self.ensure_pending_capacity_for(self.peers.len())?;
        let mut packets = Vec::with_capacity(self.peers.len());
        for peer in 0..self.peers.len() {
            let Some(session) = &mut self.peer_runtime[peer].srp else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SRP client session is not configured",
                ));
            };
            let frame = session.start();
            self.peer_runtime[peer].last_reauthentication = Some(Instant::now());
            let packet = self
                .core
                .build_eapol_for_peer(&mut self.peer_runtime[peer].sender, &frame)
                .map_err(core_to_io_error)?;
            self.enqueue_datagram(&packet.bytes, vec![self.peers[peer].addr])?;
            packets.push(MainMioPeerControlPacket { peer, packet });
        }
        self.flush_pending()?;
        Ok(packets)
    }

    pub fn send_eapol_frame_to(
        &mut self,
        peer: usize,
        frame: &EapolFrame,
    ) -> io::Result<MainControlPacket> {
        self.ensure_pending_capacity()?;
        let Some(runtime) = self.peer_runtime.get_mut(peer) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RIST peer index is not configured",
            ));
        };
        let packet = self
            .core
            .build_eapol_for_peer(&mut runtime.sender, frame)
            .map_err(core_to_io_error)?;
        self.enqueue_datagram(&packet.bytes, vec![self.peers[peer].addr])?;
        self.flush_pending()?;
        Ok(packet)
    }

    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<MainSenderEvent>> {
        let Some((from, datagram)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        let Some(peer) = self.peers.iter().position(|peer| peer.addr == from) else {
            return Ok(None);
        };
        let packet = self
            .core
            .decode_datagram_for_peer(&mut self.peer_runtime[peer].sender, datagram)
            .map_err(core_to_io_error)?;
        let event = match packet {
            MainPacket::Eapol(eapol) => {
                let accepted = self.peer_runtime[peer].srp.is_some();
                let response = self.peer_runtime[peer]
                    .srp
                    .as_mut()
                    .map(|session| session.handle_frame(&eapol.frame))
                    .transpose()
                    .map_err(core_to_io_error)?
                    .flatten();
                if let Some(response) = response {
                    self.send_eapol_frame_to(peer, &response)?;
                }
                if accepted {
                    self.peer_runtime[peer]
                        .timers
                        .observe_peer_activity(Instant::now());
                }
                if peer_authenticated(&self.peer_runtime[peer]) {
                    self.peer_runtime[peer].last_reauthentication = None;
                }
                MainSenderEvent::Eapol {
                    from,
                    frame: eapol.frame,
                }
            }
            packet if !peer_authenticated(&self.peer_runtime[peer]) => {
                MainSenderEvent::Unhandled { from, packet }
            }
            MainPacket::Reduced(packet) if looks_like_rtcp(&packet.payload) => {
                let retries = self
                    .core
                    .handle_reduced_feedback_for_peer(
                        &mut self.peer_runtime[peer].sender,
                        &packet.payload,
                    )
                    .map_err(core_to_io_error)?;
                for retry in &retries {
                    self.enqueue_datagram(&retry.bytes, vec![self.peers[peer].addr])?;
                }
                self.flush_pending()?;
                self.peer_runtime[peer]
                    .timers
                    .observe_peer_activity(Instant::now());
                MainSenderEvent::Feedback { from, retries }
            }
            MainPacket::Keepalive(packet) => {
                self.peer_runtime[peer]
                    .timers
                    .observe_peer_activity(Instant::now());
                MainSenderEvent::Keepalive { from, packet }
            }
            MainPacket::BufferNegotiation(packet) => {
                self.peer_runtime[peer]
                    .timers
                    .observe_peer_activity(Instant::now());
                MainSenderEvent::BufferNegotiation { from, packet }
            }
            MainPacket::Oob(packet) => {
                self.peer_runtime[peer]
                    .timers
                    .observe_peer_activity(Instant::now());
                MainSenderEvent::Oob { from, packet }
            }
            packet => MainSenderEvent::Unhandled { from, packet },
        };
        Ok(Some(event))
    }

    pub fn try_recv_and_dispatch(
        &mut self,
        buf: &mut [u8],
        queues: &mut MainSenderEventQueues,
    ) -> io::Result<Option<MainEventQueue>> {
        let Some(event) = self.try_recv_event(buf)? else {
            return Ok(None);
        };
        queues.push(event).map(Some).map_err(queue_full_to_io)
    }

    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<MainOutboundPacket>>> {
        match self.try_recv_event(buf)? {
            Some(MainSenderEvent::Feedback { retries, .. }) => Ok(Some(retries)),
            _ => Ok(None),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
    }

    pub fn set_multicast_if_v4(&self, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.set_multicast_if_v4(interface)
    }

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn peer_stats(&self, peer: usize) -> Option<SenderStats> {
        Some(self.peer_runtime.get(peer)?.sender.stats())
    }

    pub fn peer_last_activity(&self, peer: usize) -> Option<Instant> {
        self.peer_runtime.get(peer)?.timers.last_peer_activity()
    }

    fn select_peers(&mut self) -> io::Result<Vec<usize>> {
        if self.peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peers configured",
            ));
        }

        let selected = match self.selector.select() {
            PeerSelection::DuplicateAll => (0..self.peers.len()).collect::<Vec<_>>(),
            PeerSelection::Peer(index) => vec![index],
        };
        Ok(selected)
    }

    fn ensure_peers_authenticated(&self, peers: &[usize]) -> io::Result<()> {
        if peers
            .iter()
            .any(|&peer| !peer_authenticated(&self.peer_runtime[peer]))
        {
            Err(srp_not_authenticated_error())
        } else {
            Ok(())
        }
    }

    fn ensure_all_peers_authenticated(&self) -> io::Result<()> {
        if self.peer_runtime.iter().all(peer_authenticated) {
            Ok(())
        } else {
            Err(srp_not_authenticated_error())
        }
    }

    pub fn flush_pending(&mut self) -> io::Result<usize> {
        let mut datagrams = 0;
        while let Some(pending) = self.pending.front_mut() {
            while pending.next_destination < pending.destinations.len() {
                let destination = pending.destinations[pending.next_destination];
                match self.socket.send_packet_to(destination, &pending.bytes) {
                    Ok(len) if len == pending.bytes.len() => pending.next_destination += 1,
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "UDP send accepted a partial datagram",
                        ))
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(datagrams)
                    }
                    Err(error) => return Err(error),
                }
            }
            self.pending.pop_front();
            datagrams += 1;
        }
        Ok(datagrams)
    }

    pub fn pending_send_len(&self) -> usize {
        self.pending.len()
    }

    fn ensure_pending_capacity(&self) -> io::Result<()> {
        self.ensure_pending_capacity_for(1)
    }

    fn ensure_pending_capacity_for(&self, additional: usize) -> io::Result<()> {
        if self.pending.len().saturating_add(additional) > PENDING_SEND_CAPACITY {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RIST pending-send queue is full",
            ))
        } else {
            Ok(())
        }
    }

    fn enqueue_datagram(&mut self, packet: &[u8], destinations: Vec<SocketAddr>) -> io::Result<()> {
        self.ensure_pending_capacity()?;
        self.pending.push_back(PendingMultiDatagram {
            bytes: packet.to_vec(),
            destinations,
            next_destination: 0,
        });
        Ok(())
    }
}

fn peer_authenticated(runtime: &MainMultiSenderPeerRuntime) -> bool {
    runtime
        .srp
        .as_ref()
        .map(EapSrpClientSession::authenticated)
        .unwrap_or(true)
}

fn multi_reauthentication_due(runtime: &MainMultiSenderPeerRuntime, now: Instant) -> bool {
    if runtime.srp.is_none() {
        return false;
    }
    let Some(last_activity) = runtime.timers.last_peer_activity() else {
        return false;
    };
    let config = runtime.timers.config();
    let minimum_silence = config
        .session_timeout
        .max(config.keepalive_interval.saturating_mul(4));
    if now.saturating_duration_since(last_activity) <= minimum_silence {
        return false;
    }
    runtime.last_reauthentication.map_or(true, |last| {
        now.saturating_duration_since(last) >= config.session_timeout
    })
}

pub struct MainMioReceiver {
    socket: RtpUdpSocket,
    core: MainReceiverCore,
    timers: MainSessionTimers,
    last_peer: Option<SocketAddr>,
    srp: Option<EapSrpAuthenticatorSession>,
    srp_client: Option<EapSrpClientSession>,
    configured_peer: Option<SocketAddr>,
    peer_runtime: HashMap<SocketAddr, MainReceiverPeerRuntime>,
    max_peers: usize,
}

struct MainReceiverPeerRuntime {
    core: MainReceiverCore,
    timers: MainSessionTimers,
    srp: Option<EapSrpAuthenticatorSession>,
    srp_client: Option<EapSrpClientSession>,
}

impl MainMioReceiver {
    pub fn bind(
        local: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: MainReceiverCore::new(flow_id, cname, nack_mode),
            timers: MainSessionTimers::new(),
            last_peer: None,
            srp: None,
            srp_client: None,
            configured_peer: None,
            peer_runtime: HashMap::new(),
            max_peers: DEFAULT_MAIN_PEER_CAPACITY,
        })
    }

    pub fn bind_reuse(
        local: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind_reuse(local, flow_id)?,
            core: MainReceiverCore::new(flow_id, cname, nack_mode),
            timers: MainSessionTimers::new(),
            last_peer: None,
            srp: None,
            srp_client: None,
            configured_peer: None,
            peer_runtime: HashMap::new(),
            max_peers: DEFAULT_MAIN_PEER_CAPACITY,
        })
    }

    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: MainReceiverCore::new(flow_id, cname, nack_mode),
            timers: MainSessionTimers::new(),
            last_peer: Some(peer),
            srp: None,
            srp_client: None,
            configured_peer: Some(peer),
            peer_runtime: HashMap::new(),
            max_peers: 1,
        })
    }

    pub fn try_recv_payload(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, ReceivedPayload)>> {
        match self.try_recv_event(buf)? {
            Some(MainReceiverEvent::Payload { from, payload }) => Ok(Some((from, payload))),
            _ => Ok(None),
        }
    }

    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<MainReceiverEvent>> {
        let Some((from, datagram)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if self.configured_peer.is_some_and(|peer| peer != from) {
            return Ok(None);
        }
        if !self.peer_runtime.contains_key(&from) && self.peer_runtime.len() >= self.max_peers {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("RIST Main receiver peer capacity is {}", self.max_peers),
            ));
        }
        let core = self.core.fresh_session();
        let timers = MainSessionTimers::with_config(self.timers.config());
        let srp = self.srp.clone();
        let srp_client = self.srp_client.clone();
        let runtime = self
            .peer_runtime
            .entry(from)
            .or_insert_with(|| MainReceiverPeerRuntime {
                core,
                timers,
                srp,
                srp_client,
            });
        let packet = runtime
            .core
            .decode_datagram(datagram)
            .map_err(core_to_io_error)?;
        let now = Instant::now();
        let mut completed_authentication = false;
        let event = match packet {
            MainPacket::Eapol(eapol) => {
                let authenticated_before = receiver_runtime_authenticated(runtime);
                let (response, accepted) = handle_receiver_runtime_eapol(runtime, &eapol.frame)?;
                completed_authentication =
                    !authenticated_before && receiver_runtime_authenticated(runtime);
                if let Some(response) = response {
                    let packet = runtime
                        .core
                        .build_eapol(&response)
                        .map_err(core_to_io_error)?;
                    self.socket.send_packet_to(from, &packet.bytes)?;
                }
                if accepted {
                    runtime.timers.observe_peer_activity(now);
                    self.last_peer = Some(from);
                }
                MainReceiverEvent::Eapol {
                    from,
                    frame: eapol.frame,
                }
            }
            packet if !receiver_runtime_authenticated(runtime) => {
                return Ok(Some(MainReceiverEvent::Unhandled { from, packet }));
            }
            MainPacket::Reduced(packet) if looks_like_rtcp(&packet.payload) => {
                let responses = runtime
                    .core
                    .handle_reduced_rtcp(packet.reduced, &packet.payload, ntp_now())
                    .map_err(core_to_io_error)?;
                for response in &responses {
                    self.socket.send_packet_to(from, &response.bytes)?;
                }
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                MainReceiverEvent::Rtcp { from, responses }
            }
            MainPacket::Reduced(packet) => {
                let payload = runtime
                    .core
                    .accept_reduced(packet.reduced, &packet.payload)
                    .map_err(core_to_io_error)?;
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                MainReceiverEvent::Payload { from, payload }
            }
            MainPacket::Keepalive(packet) => {
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                MainReceiverEvent::Keepalive { from, packet }
            }
            MainPacket::BufferNegotiation(packet) => {
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                MainReceiverEvent::BufferNegotiation { from, packet }
            }
            MainPacket::Oob(packet) => {
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                MainReceiverEvent::Oob { from, packet }
            }
            packet => MainReceiverEvent::Unhandled { from, packet },
        };
        if completed_authentication {
            self.reassociate_authenticated_peer(from, now);
        }
        Ok(Some(event))
    }

    pub fn try_recv_and_dispatch(
        &mut self,
        buf: &mut [u8],
        queues: &mut MainReceiverEventQueues,
    ) -> io::Result<Option<MainEventQueue>> {
        let Some(event) = self.try_recv_event(buf)? else {
            return Ok(None);
        };
        queues.push(event).map(Some).map_err(queue_full_to_io)
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core
            .set_recovery_config(recovery.clone(), congestion_control);
        for runtime in self.peer_runtime.values_mut() {
            runtime
                .core
                .set_recovery_config(recovery.clone(), congestion_control);
        }
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.core.set_tx_key(key.clone());
        for runtime in self.peer_runtime.values_mut() {
            runtime.core.set_tx_key(key.clone());
        }
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
        self.core.set_rx_key(key.clone());
        for runtime in self.peer_runtime.values_mut() {
            runtime.core.set_rx_key(key.clone());
        }
    }

    pub fn session_config(&self) -> MainSessionConfig {
        self.timers.config()
    }

    pub fn peer_count(&self) -> usize {
        self.peer_runtime.len()
    }

    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    pub fn set_runtime_limits(
        &mut self,
        max_peers: usize,
        max_flows_per_peer: usize,
    ) -> io::Result<()> {
        if max_peers == 0 || self.peer_runtime.len() > max_peers {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Main receiver peer limit is smaller than the current runtime",
            ));
        }
        if max_flows_per_peer == 0
            || self.core.flow_count() > max_flows_per_peer
            || self
                .peer_runtime
                .values()
                .any(|runtime| runtime.core.flow_count() > max_flows_per_peer)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Main receiver flow limit is smaller than the current runtime",
            ));
        }
        self.core
            .set_max_flows(max_flows_per_peer)
            .map_err(core_to_io_error)?;
        for runtime in self.peer_runtime.values_mut() {
            runtime
                .core
                .set_max_flows(max_flows_per_peer)
                .map_err(core_to_io_error)?;
        }
        self.max_peers = max_peers;
        Ok(())
    }

    pub fn peer_flow_count(&self, peer: SocketAddr) -> Option<usize> {
        self.peer_runtime
            .get(&peer)
            .map(|runtime| runtime.core.flow_count())
    }

    pub fn peer_flow_ids(&self, peer: SocketAddr) -> Option<Vec<u32>> {
        self.peer_runtime
            .get(&peer)
            .map(|runtime| runtime.core.flow_ids())
    }

    pub fn peer_flow_stats(&self, peer: SocketAddr, flow_id: u32) -> Option<ReceiverStats> {
        self.peer_runtime.get(&peer)?.core.stats_for_flow(flow_id)
    }

    pub fn peer_missing_sequences(&self, peer: SocketAddr, flow_id: u32) -> Option<Vec<u32>> {
        self.peer_runtime
            .get(&peer)?
            .core
            .missing_sequences_for_flow(flow_id)
    }

    pub fn peer_authenticated(&self, peer: SocketAddr) -> Option<bool> {
        self.peer_runtime
            .get(&peer)
            .map(receiver_runtime_authenticated)
    }

    fn reassociate_authenticated_peer(&mut self, new_addr: SocketAddr, now: Instant) -> bool {
        let Some(identity) = self
            .peer_runtime
            .get(&new_addr)
            .and_then(|runtime| runtime.srp.as_ref())
            .and_then(EapSrpAuthenticatorSession::authenticated_username)
            .map(str::to_owned)
        else {
            return false;
        };

        let mut stale_candidate = None;
        let mut stale_candidates = 0usize;
        let mut live_duplicates = 0usize;
        for (&addr, runtime) in &self.peer_runtime {
            if addr == new_addr
                || runtime
                    .srp
                    .as_ref()
                    .and_then(EapSrpAuthenticatorSession::authenticated_username)
                    != Some(identity.as_str())
            {
                continue;
            }
            if runtime.timers.is_timed_out(now) {
                stale_candidate = Some(addr);
                stale_candidates += 1;
            } else {
                live_duplicates += 1;
            }
        }
        if stale_candidates != 1 || live_duplicates != 0 {
            return false;
        }

        let old_addr = stale_candidate.expect("one stale peer was counted");
        let Some(new_runtime) = self.peer_runtime.remove(&new_addr) else {
            return false;
        };
        let Some(mut recovered_runtime) = self.peer_runtime.remove(&old_addr) else {
            self.peer_runtime.insert(new_addr, new_runtime);
            return false;
        };
        recovered_runtime.srp = new_runtime.srp;
        recovered_runtime.timers = new_runtime.timers;
        self.peer_runtime.insert(new_addr, recovered_runtime);
        if self.last_peer == Some(old_addr) {
            self.last_peer = Some(new_addr);
        }
        true
    }

    pub fn poll_peer_session(&mut self, peer: SocketAddr, now: Instant) -> Option<MainSessionPoll> {
        self.peer_runtime
            .get_mut(&peer)
            .map(|runtime| runtime.timers.poll(now))
    }

    pub fn poll_peer_rtcp_and_send(
        &mut self,
        peer: SocketAddr,
        now: Instant,
        now_ntp: u64,
    ) -> io::Result<Option<Vec<MainReceiverFeedback>>> {
        let Some(runtime) = self.peer_runtime.get_mut(&peer) else {
            return Ok(None);
        };
        let packets = runtime.core.poll_rtcp_all(now, now_ntp);
        let mut sent = Vec::with_capacity(packets.len());
        for (_, packet) in packets {
            self.socket.send_packet_to(peer, &packet.bytes)?;
            sent.push(packet);
        }
        Ok(Some(sent))
    }

    pub fn set_session_config(&mut self, config: MainSessionConfig) {
        self.timers.set_config(config);
        for runtime in self.peer_runtime.values_mut() {
            runtime.timers.set_config(config);
        }
    }

    pub fn observe_peer_activity(&mut self, now: Instant) {
        self.timers.observe_peer_activity(now);
    }

    pub fn poll_session(&mut self, now: Instant) -> MainSessionPoll {
        match self
            .last_peer
            .and_then(|peer| self.peer_runtime.get_mut(&peer))
        {
            Some(runtime) => runtime.timers.poll(now),
            None => self.timers.poll(now),
        }
    }

    pub fn poll_session_and_send_keepalive(
        &mut self,
        now: Instant,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainMioSessionPoll> {
        let poll = self.poll_session(now);
        let keepalive = if poll.keepalive_due {
            match self.last_peer {
                Some(peer) => Some(self.send_keepalive_to(peer, keepalive)?),
                None => None,
            }
        } else {
            None
        };
        Ok(MainMioSessionPoll { poll, keepalive })
    }

    pub fn enable_srp_authenticator(&mut self, store: SrpCredentialStore) {
        let session = EapSrpAuthenticatorSession::new(store).with_session_key_passphrase(false);
        self.srp = Some(session.clone());
        self.srp_client = None;
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp = Some(session.clone());
            runtime.srp_client = None;
        }
    }

    pub fn enable_srp_client(&mut self, username: impl Into<String>, password: impl AsRef<[u8]>) {
        self.set_srp_client_session(
            EapSrpClientSession::new(username, password).with_session_key_passphrase(false),
        );
    }

    pub fn set_srp_client_session(&mut self, session: EapSrpClientSession) {
        self.srp = None;
        self.srp_client = Some(session.clone());
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp = None;
            runtime.srp_client = Some(session.clone());
        }
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> io::Result<()> {
        let Some(session) = &mut self.srp_client else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        session.set_password(password.as_ref());
        let template = self.srp_client.clone();
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp_client.clone_from(&template);
        }
        Ok(())
    }

    pub fn start_srp_authentication(&mut self) -> io::Result<MainControlPacket> {
        let peer = self.configured_peer.ok_or_else(no_remote_peer_error)?;
        let frame = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime
                .srp_client
                .as_mut()
                .ok_or_else(srp_client_not_configured_error)?
                .start(),
            None => self
                .srp_client
                .as_mut()
                .ok_or_else(srp_client_not_configured_error)?
                .start(),
        };
        self.send_eapol_frame_to(peer, &frame)
    }

    pub fn stage_srp_password(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> io::Result<SrpUserRecord> {
        let Some(session) = &mut self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP authenticator session is not configured",
            ));
        };
        let record = session
            .stage_password(username, password)
            .map_err(core_to_io_error)?;
        let template = self.srp.clone();
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp.clone_from(&template);
        }
        Ok(record)
    }

    pub fn retire_srp_generations_before(
        &mut self,
        username: &str,
        generation: u64,
    ) -> io::Result<()> {
        let Some(session) = &mut self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP authenticator session is not configured",
            ));
        };
        session.retire_generations_before(username, generation);
        let template = self.srp.clone();
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp.clone_from(&template);
        }
        Ok(())
    }

    pub fn current_srp_generation(&self, username: &str) -> Option<u64> {
        self.srp
            .as_ref()
            .and_then(|session| session.current_generation(username))
    }

    pub fn set_srp_authenticator_session(&mut self, session: EapSrpAuthenticatorSession) {
        self.srp = Some(session.clone());
        self.srp_client = None;
        for runtime in self.peer_runtime.values_mut() {
            runtime.srp = Some(session.clone());
            runtime.srp_client = None;
        }
    }

    pub fn srp_authenticated(&self) -> bool {
        self.last_peer
            .and_then(|peer| self.peer_runtime.get(&peer))
            .map(receiver_runtime_authenticated)
            .unwrap_or_else(|| {
                if let Some(session) = &self.srp {
                    session.authenticated()
                } else if let Some(session) = &self.srp_client {
                    session.authenticated()
                } else {
                    true
                }
            })
    }

    pub fn send_feedback(&mut self) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_peer else {
            return Ok(None);
        };
        self.send_feedback_to(peer).map(Some)
    }

    pub fn send_feedback_to(&mut self, peer: SocketAddr) -> io::Result<usize> {
        self.ensure_peer_authenticated(peer)?;
        let feedback = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.build_feedback(),
            None => self.core.build_feedback(),
        };
        self.socket.send_packet_to(peer, &feedback.bytes)
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        now_ntp: u64,
    ) -> io::Result<Option<MainReceiverFeedback>> {
        let Some(peer) = self.last_peer else {
            return Ok(None);
        };
        self.ensure_peer_authenticated(peer)?;
        let packet = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.poll_rtcp(now, now_ntp),
            None => self.core.poll_rtcp(now, now_ntp),
        };
        let Some(packet) = packet else {
            return Ok(None);
        };
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(Some(packet))
    }

    pub fn try_recv_rtcp_and_respond(
        &mut self,
        buf: &mut [u8],
        _now_ntp: u64,
    ) -> io::Result<Option<usize>> {
        match self.try_recv_event(buf)? {
            Some(MainReceiverEvent::Rtcp { responses, .. }) => Ok(Some(responses.len())),
            _ => Ok(None),
        }
    }

    pub fn send_keepalive_to(
        &mut self,
        peer: SocketAddr,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainControlPacket> {
        let packet = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.build_keepalive(keepalive),
            None => self.core.build_keepalive(keepalive),
        };
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn send_buffer_negotiation_to(
        &mut self,
        peer: SocketAddr,
        negotiation: BufferNegotiation<'_>,
    ) -> io::Result<MainControlPacket> {
        self.ensure_peer_authenticated(peer)?;
        let packet = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.build_buffer_negotiation(negotiation),
            None => self.core.build_buffer_negotiation(negotiation),
        };
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn send_eapol_frame_to(
        &mut self,
        peer: SocketAddr,
        frame: &EapolFrame,
    ) -> io::Result<MainControlPacket> {
        let packet = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.build_eapol(frame),
            None => self.core.build_eapol(frame),
        }
        .map_err(core_to_io_error)?;
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn send_oob_to(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
    ) -> io::Result<MainControlPacket> {
        self.ensure_peer_authenticated(peer)?;
        let packet = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => runtime.core.build_oob(payload),
            None => self.core.build_oob(payload),
        };
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<EapolFrame>> {
        match self.try_recv_event(buf)? {
            Some(MainReceiverEvent::Eapol { frame, .. }) => Ok(Some(frame)),
            _ => Ok(None),
        }
    }

    pub fn try_recv_keepalive(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedKeepalivePacket)>> {
        match self.try_recv_event(buf)? {
            Some(MainReceiverEvent::Keepalive { from, packet }) => Ok(Some((from, packet))),
            _ => Ok(None),
        }
    }

    pub fn try_recv_buffer_negotiation(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedBufferNegotiationPacket)>> {
        match self.try_recv_event(buf)? {
            Some(MainReceiverEvent::BufferNegotiation { from, packet }) => Ok(Some((from, packet))),
            _ => Ok(None),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.configured_peer.or(self.last_peer)
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.leave_multicast_v4(multiaddr, interface)
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.last_peer
            .and_then(|peer| self.peer_runtime.get(&peer))
            .map(|runtime| runtime.core.missing_sequences())
            .unwrap_or_else(|| self.core.missing_sequences())
    }

    pub fn stats(&self) -> ReceiverStats {
        self.last_peer
            .and_then(|peer| self.peer_runtime.get(&peer))
            .map(|runtime| runtime.core.stats())
            .unwrap_or_else(|| self.core.stats())
    }

    fn ensure_peer_authenticated(&self, peer: SocketAddr) -> io::Result<()> {
        let authenticated = self
            .peer_runtime
            .get(&peer)
            .map(receiver_runtime_authenticated)
            .unwrap_or_else(|| self.srp_authenticated());
        if authenticated {
            Ok(())
        } else {
            Err(srp_not_authenticated_error())
        }
    }
}

fn receiver_runtime_authenticated(runtime: &MainReceiverPeerRuntime) -> bool {
    if let Some(session) = &runtime.srp {
        session.authenticated()
    } else if let Some(session) = &runtime.srp_client {
        session.authenticated()
    } else {
        true
    }
}

fn handle_receiver_runtime_eapol(
    runtime: &mut MainReceiverPeerRuntime,
    frame: &EapolFrame,
) -> io::Result<(Option<EapolFrame>, bool)> {
    if let Some(session) = &mut runtime.srp {
        let authenticated = session.authenticated();
        return match session.handle_frame(frame) {
            Ok(response) => Ok((response, true)),
            Err(rist_core::Error::InvalidEapPacket) if authenticated => Ok((None, false)),
            Err(error) => Err(core_to_io_error(error)),
        };
    }
    if let Some(session) = &mut runtime.srp_client {
        let authenticated = session.authenticated();
        return match session.handle_frame(frame) {
            Ok(response) => Ok((response, true)),
            Err(rist_core::Error::InvalidEapPacket) if authenticated => Ok((None, false)),
            Err(error) => Err(core_to_io_error(error)),
        };
    }
    Ok((None, false))
}

fn srp_client_not_configured_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "SRP client session is not configured",
    )
}

fn core_to_io_error(err: rist_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn queue_full_to_io<E>(error: MainEventQueueFull<E>) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
            "RIST {:?} event queue is full at {} packets",
            error.queue, error.capacity
        ),
    )
}

fn looks_like_rtcp(payload: &[u8]) -> bool {
    payload.len() >= 2 && (72..=77).contains(&(payload[1] & 0x7f))
}

fn srp_not_authenticated_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "SRP authentication has not completed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_core::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use rist_core::packet::gre::{GreHeader, ReducedPacket};
    use rist_core::packet::rtp::RtpPacket;
    use rist_core::time::ntp_from_unix_duration;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
    use std::thread;
    use std::time::Duration;

    fn loopback_any() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[cfg(unix)]
    #[test]
    fn normalizes_enobufs_to_would_block() {
        let error = normalize_udp_send_error(io::Error::from_raw_os_error(libc::ENOBUFS));

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let source = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("normalized error must retain the operating-system error");
        assert_eq!(source.raw_os_error(), Some(libc::ENOBUFS));
    }

    #[test]
    fn preserves_non_enobufs_send_errors() {
        let error = normalize_udp_send_error(io::Error::from(io::ErrorKind::ConnectionRefused));

        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.get_ref().is_none());
    }

    #[test]
    fn full_pending_queue_rejects_before_sequence_and_history_commit() {
        let receiver =
            SimpleMioReceiver::bind(loopback_any(), 0x1122_3344, "receiver", NackMode::Range)
                .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let now = Instant::now();
        let ntp = ntp_now();

        let mut simple = SimpleMioSender::connect(local, receiver_addr, 0x1122_3344, 64).unwrap();
        simple
            .pending
            .resize_with(PENDING_SEND_CAPACITY, || PendingDatagram {
                bytes: vec![0u8; 1],
                peer: receiver_addr,
            });
        let error = simple.send_payload(b"not-accepted", ntp, now).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(simple.core.next_sequence(), 0);

        let mut main = MainMioSender::connect(local, receiver_addr, 0x5566_7788, 64).unwrap();
        main.pending
            .resize_with(PENDING_SEND_CAPACITY, || PendingDatagram {
                bytes: vec![0u8; 1],
                peer: receiver_addr,
            });
        let error = main.send_payload(b"not-accepted", ntp, now).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        main.pending.clear();
        assert_eq!(
            main.build_payload(b"first-accepted", ntp, now).rtp_sequence,
            0
        );
    }

    #[test]
    fn simple_profile_receiver_caller_discovers_sender_listener() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = SimpleMioSender::listen(loopback_any(), flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut receiver = SimpleMioReceiver::connect(
            loopback_any(),
            sender_addr,
            flow_id,
            "caller",
            NackMode::Range,
        )
        .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let error = sender.send_payload(b"too-early", ntp, now).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(sender.core.next_sequence(), 0);

        receiver.send_feedback().unwrap().unwrap();
        let mut feedback_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while sender.peer_addr().is_none() {
            sender
                .try_recv_feedback_and_retransmit(&mut feedback_buf)
                .unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for Simple caller discovery"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.peer_addr(), Some(receiver_addr));

        sender.send_payload(b"reverse-simple", ntp, now).unwrap();
        let mut payload_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.try_recv_payload(&mut payload_buf).unwrap() {
                Some((from, payload)) => {
                    assert_eq!(from, sender_addr);
                    assert_eq!(payload.payload, b"reverse-simple");
                    break;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for reverse Simple payload"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    #[test]
    fn main_profile_receiver_caller_discovers_sender_listener() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainMioSender::listen(loopback_any(), flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut receiver = MainMioReceiver::connect(
            loopback_any(),
            sender_addr,
            flow_id,
            "caller",
            NackMode::Range,
        )
        .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let error = sender.send_payload(b"too-early", ntp, now).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        receiver
            .send_keepalive_to(
                sender_addr,
                GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
            )
            .unwrap();

        let mut sender_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match sender.try_recv_event(&mut sender_buf).unwrap() {
                Some(MainSenderEvent::Keepalive { from, .. }) => {
                    assert_eq!(from, receiver_addr);
                    break;
                }
                Some(event) => panic!("unexpected Main sender event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for Main caller discovery"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert_eq!(sender.peer_addr(), Some(receiver_addr));

        sender.send_payload(b"reverse-main", ntp, now).unwrap();
        let mut receiver_buf = [0u8; 1500];
        let payload = recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(payload.payload, b"reverse-main");
    }

    #[test]
    fn main_profile_reverse_roles_use_caller_and_listener_srp_roles() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut sender = MainMioSender::listen(loopback_any(), flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"reverse-roles").unwrap();
        sender.enable_srp_authenticator(store);

        let mut receiver = MainMioReceiver::connect(
            loopback_any(),
            sender_addr,
            flow_id,
            "caller",
            NackMode::Range,
        )
        .unwrap();
        receiver.enable_srp_client("rist", b"reverse-roles");
        receiver
            .send_keepalive_to(
                sender_addr,
                GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
            )
            .unwrap();
        receiver.start_srp_authentication().unwrap();

        let mut sender_buf = [0u8; 2048];
        let mut receiver_buf = [0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(2);
        while !sender.srp_authenticated() || !receiver.srp_authenticated() {
            sender.try_recv_event(&mut sender_buf).unwrap();
            receiver.try_recv_event(&mut receiver_buf).unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out authenticating reverse Main roles"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.peer_addr(), Some(receiver.local_addr().unwrap()));
        assert_eq!(receiver.peer_addr(), Some(sender_addr));

        sender
            .send_payload(b"authenticated-reverse-main", ntp, Instant::now())
            .unwrap();
        let payload = recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(payload.payload, b"authenticated-reverse-main");
    }

    #[test]
    fn main_profile_dispatches_udp_traffic_into_isolated_bounded_queues() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let now = Instant::now();
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();

        sender.send_payload(b"first", ntp, now).unwrap();
        sender.send_payload(b"second", ntp, now).unwrap();
        assert!(sender.poll_rtcp_and_send(now, ntp).unwrap().is_none());
        sender
            .poll_rtcp_and_send(now + Duration::from_secs(1), ntp)
            .unwrap()
            .unwrap();
        sender.send_eapol_frame(&EapolFrame::start(3)).unwrap();
        sender
            .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
            .unwrap();
        sender
            .send_buffer_negotiation(BufferNegotiation::session(1000, 250))
            .unwrap();
        sender.send_oob(b"tunnel packet").unwrap();

        let unknown_socket = StdUdpSocket::bind(loopback_any()).unwrap();
        let mut unknown = Vec::new();
        GreHeader {
            protocol_type: 0x1234,
            version: 1,
            key: None,
            sequence: Some(99),
        }
        .encode(&mut unknown);
        unknown.extend_from_slice(b"opaque control");
        unknown_socket.send_to(&unknown, receiver_addr).unwrap();

        let mut queues = MainReceiverEventQueues::new(1);
        let mut buf = [0u8; 1500];
        let mut consumed = 0;
        let mut full = 0;
        let deadline = Instant::now() + Duration::from_secs(1);
        while consumed < 8 {
            match receiver.try_recv_and_dispatch(&mut buf, &mut queues) {
                Ok(Some(_)) => consumed += 1,
                Ok(None) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for dispatched traffic"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    consumed += 1;
                    full += 1;
                }
                Err(error) => panic!("dispatch failed: {error}"),
            }
        }

        assert_eq!(full, 1);
        for queue in [
            MainEventQueue::Data,
            MainEventQueue::Rtcp,
            MainEventQueue::Eapol,
            MainEventQueue::Keepalive,
            MainEventQueue::BufferNegotiation,
            MainEventQueue::Oob,
            MainEventQueue::Unknown,
        ] {
            assert_eq!(queues.len(queue), 1, "{queue:?} queue");
            assert_eq!(queues.capacity(queue), 1, "{queue:?} capacity");
        }
        assert_eq!(queues.dropped(MainEventQueue::Data), 1);
        assert_eq!(queues.dropped(MainEventQueue::Oob), 0);

        assert!(matches!(
            queues.pop(MainEventQueue::Data),
            Some(MainReceiverEvent::Payload { payload, .. }) if payload.payload == b"first"
        ));
        assert!(matches!(
            queues.pop(MainEventQueue::Oob),
            Some(MainReceiverEvent::Oob { packet, .. }) if packet.payload == b"tunnel packet"
        ));
        assert!(matches!(
            queues.pop(MainEventQueue::Unknown),
            Some(MainReceiverEvent::Unhandled {
                packet: MainPacket::Unknown { payload, .. },
                ..
            }) if payload == b"opaque control"
        ));
    }

    #[test]
    fn main_profile_isolates_recovery_state_by_peer_and_flow() {
        let flow_a = 0x2000;
        let flow_b = 0x3000;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let now = Instant::now();
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_a, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let peer_a = StdUdpSocket::bind(loopback_any()).unwrap();
        let peer_b = StdUdpSocket::bind(loopback_any()).unwrap();
        let peer_a_addr = peer_a.local_addr().unwrap();
        let peer_b_addr = peer_b.local_addr().unwrap();

        let mut peer_a_flow_a = MainSenderCore::new(flow_a, 64);
        let mut peer_a_flow_b = MainSenderCore::new(flow_b, 64);
        let mut peer_b_flow_a = MainSenderCore::new(flow_a, 64);

        let peer_a_first = peer_a_flow_a.send_payload(b"peer-a-flow-a-0", ntp, now);
        let _peer_a_lost = peer_a_flow_a.send_payload(b"peer-a-flow-a-1", ntp, now);
        let peer_a_third = peer_a_flow_a.send_payload(b"peer-a-flow-a-2", ntp, now);
        let peer_a_other_flow = peer_a_flow_b.send_payload(b"peer-a-flow-b-0", ntp, now);
        let peer_b_first = peer_b_flow_a.send_payload(b"peer-b-flow-a-0", ntp, now);
        let peer_b_second = peer_b_flow_a.send_payload(b"peer-b-flow-a-1", ntp, now);

        for packet in [&peer_a_first, &peer_a_third, &peer_a_other_flow] {
            peer_a.send_to(&packet.bytes, receiver_addr).unwrap();
        }
        for packet in [&peer_b_first, &peer_b_second] {
            peer_b.send_to(&packet.bytes, receiver_addr).unwrap();
        }

        let mut received = Vec::new();
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while received.len() < 5 {
            match receiver.try_recv_event(&mut buf).unwrap() {
                Some(MainReceiverEvent::Payload { from, payload }) => {
                    assert!(!payload.duplicate);
                    received.push((from, payload));
                }
                Some(event) => panic!("unexpected Main receiver event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for peer/flow traffic"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }

        assert_eq!(receiver.peer_count(), 2);
        assert_eq!(receiver.peer_flow_count(peer_a_addr), Some(2));
        assert_eq!(
            receiver.peer_flow_ids(peer_a_addr),
            Some(vec![flow_a, flow_b])
        );
        assert_eq!(receiver.peer_flow_count(peer_b_addr), Some(1));

        let peer_a_stats = receiver.peer_flow_stats(peer_a_addr, flow_a).unwrap();
        assert_eq!(peer_a_stats.received_packets, 2);
        assert_eq!(peer_a_stats.currently_missing_packets, 1);
        assert_eq!(
            receiver.peer_missing_sequences(peer_a_addr, flow_a),
            Some(vec![1])
        );

        let peer_a_other_stats = receiver.peer_flow_stats(peer_a_addr, flow_b).unwrap();
        assert_eq!(peer_a_other_stats.received_packets, 1);
        assert_eq!(peer_a_other_stats.currently_missing_packets, 0);

        let peer_b_stats = receiver.peer_flow_stats(peer_b_addr, flow_a).unwrap();
        assert_eq!(peer_b_stats.received_packets, 2);
        assert_eq!(peer_b_stats.currently_missing_packets, 0);
        assert_eq!(peer_b_stats.duplicate_packets, 0);
        assert_eq!(receiver.peer_authenticated(peer_a_addr), Some(true));
        assert_eq!(receiver.peer_authenticated(peer_b_addr), Some(true));

        assert!(receiver
            .poll_peer_rtcp_and_send(peer_a_addr, now, ntp)
            .unwrap()
            .unwrap()
            .is_empty());
        let feedback = receiver
            .poll_peer_rtcp_and_send(peer_a_addr, now + Duration::from_millis(80), ntp)
            .unwrap()
            .unwrap();
        assert_eq!(feedback.len(), 1);
        assert_eq!(
            receiver
                .peer_flow_stats(peer_a_addr, flow_a)
                .unwrap()
                .feedback_packets,
            1
        );
        assert_eq!(
            receiver
                .peer_flow_stats(peer_a_addr, flow_b)
                .unwrap()
                .feedback_packets,
            0
        );
        assert_eq!(
            receiver
                .peer_flow_stats(peer_b_addr, flow_a)
                .unwrap()
                .feedback_packets,
            0
        );
    }

    #[test]
    fn main_profile_isolates_authentication_and_liveness_by_peer() {
        let flow_id = 0x2000;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let now = Instant::now();
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_session_config(MainSessionConfig {
            keepalive_interval: Duration::from_secs(1),
            session_timeout: Duration::ZERO,
        });
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"per-peer").unwrap();
        receiver.enable_srp_authenticator(store);
        let receiver_addr = receiver.local_addr().unwrap();

        let mut authenticated_sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        authenticated_sender.enable_srp_client("rist", b"per-peer");
        let authenticated_addr = authenticated_sender.local_addr().unwrap();
        let mut unauthenticated_sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        let unauthenticated_addr = unauthenticated_sender.local_addr().unwrap();

        authenticated_sender.start_srp_authentication().unwrap();
        let mut receiver_buf = [0u8; 1500];
        let mut sender_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(2);
        while !authenticated_sender.srp_authenticated()
            || receiver.peer_authenticated(authenticated_addr) != Some(true)
        {
            receiver.try_recv_event(&mut receiver_buf).unwrap();
            authenticated_sender
                .try_recv_event(&mut sender_buf)
                .unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for per-peer SRP authentication"
            );
            thread::sleep(Duration::from_millis(1));
        }

        authenticated_sender
            .send_payload(b"authenticated", ntp, now)
            .unwrap();
        let accepted = loop {
            match receiver.try_recv_event(&mut receiver_buf).unwrap() {
                Some(event) => break event,
                None => thread::sleep(Duration::from_millis(1)),
            }
        };
        assert!(matches!(
            accepted,
            MainReceiverEvent::Payload { from, payload }
                if from == authenticated_addr && payload.payload == b"authenticated"
        ));

        unauthenticated_sender
            .send_payload(b"must-not-pass", ntp, now)
            .unwrap();
        let rejected = loop {
            match receiver.try_recv_event(&mut receiver_buf).unwrap() {
                Some(event) => break event,
                None => thread::sleep(Duration::from_millis(1)),
            }
        };
        assert!(matches!(
            rejected,
            MainReceiverEvent::Unhandled {
                from,
                packet: MainPacket::Reduced(_),
            } if from == unauthenticated_addr
        ));

        assert_eq!(receiver.peer_authenticated(authenticated_addr), Some(true));
        assert_eq!(
            receiver.peer_authenticated(unauthenticated_addr),
            Some(false)
        );
        assert!(
            receiver
                .poll_peer_session(authenticated_addr, Instant::now())
                .unwrap()
                .timed_out
        );
        assert!(
            !receiver
                .poll_peer_session(unauthenticated_addr, Instant::now())
                .unwrap()
                .timed_out
        );
    }

    #[test]
    fn main_profile_bounds_peer_and_flow_runtime_state() {
        let flow_a = 0x2000;
        let flow_b = 0x3000;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let now = Instant::now();
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_a, "rust", NackMode::Range).unwrap();
        receiver.set_runtime_limits(1, 1).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let peer_a = StdUdpSocket::bind(loopback_any()).unwrap();
        let peer_b = StdUdpSocket::bind(loopback_any()).unwrap();
        let peer_a_addr = peer_a.local_addr().unwrap();
        let mut peer_a_flow_a = MainSenderCore::new(flow_a, 8);
        let mut peer_a_flow_b = MainSenderCore::new(flow_b, 8);
        let mut peer_b_flow_a = MainSenderCore::new(flow_a, 8);
        let mut buf = [0u8; 1500];

        let accepted = peer_a_flow_a.send_payload(b"accepted", ntp, now);
        peer_a.send_to(&accepted.bytes, receiver_addr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if receiver.try_recv_event(&mut buf).unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "timed out waiting for peer");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(receiver.peer_count(), 1);
        assert_eq!(receiver.peer_flow_count(peer_a_addr), Some(1));

        let excess_flow = peer_a_flow_b.send_payload(b"excess-flow", ntp, now);
        peer_a.send_to(&excess_flow.bytes, receiver_addr).unwrap();
        let flow_error = loop {
            match receiver.try_recv_event(&mut buf) {
                Err(error) => break error,
                Ok(None) => {
                    assert!(Instant::now() < deadline, "timed out waiting for flow");
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(Some(event)) => panic!("unexpected event beyond flow limit: {event:?}"),
            }
        };
        assert_eq!(flow_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(receiver.peer_flow_count(peer_a_addr), Some(1));

        let excess_peer = peer_b_flow_a.send_payload(b"excess-peer", ntp, now);
        peer_b.send_to(&excess_peer.bytes, receiver_addr).unwrap();
        let peer_error = loop {
            match receiver.try_recv_event(&mut buf) {
                Err(error) => break error,
                Ok(None) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for excess peer"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(Some(event)) => panic!("unexpected event beyond peer limit: {event:?}"),
            }
        };
        assert_eq!(peer_error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(receiver.peer_count(), 1);
    }

    #[test]
    fn main_profile_rtcp_dispatch_matches_librist_payload_type_rules() {
        assert!(looks_like_rtcp(&[0x80, 72]));
        assert!(looks_like_rtcp(&[0x80, 200]));
        assert!(looks_like_rtcp(&[0x80, 77]));
        assert!(looks_like_rtcp(&[0x80, 205]));
        assert!(!looks_like_rtcp(&[0x80, 71]));
        assert!(!looks_like_rtcp(&[0x80, 78]));
        assert!(!looks_like_rtcp(&[0x80, 223]));
    }

    #[test]
    fn sends_and_receives_rtp_payload() {
        let mut rx = RtpUdpSocket::bind(loopback_any(), 1).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let mut tx = RtpUdpSocket::connect(loopback_any(), rx_addr, 0x1234).unwrap();

        tx.send_mpegts_payload(90_000, b"payload").unwrap();

        let mut buf = [0u8; 1500];
        let (_from, packet) = loop {
            if let Some(packet) = rx.recv_packet(&mut buf).unwrap() {
                break packet;
            }
        };
        assert_eq!(packet.header.ssrc, 0x1234);
        assert_eq!(packet.header.sequence_number, 0);
        assert_eq!(packet.payload, b"payload");
    }

    #[test]
    fn rtp_udp_socket_supports_reuse_bind_and_multicast_interface() {
        let first = RtpUdpSocket::bind_reuse(loopback_any(), 1).unwrap();
        let first_addr = first.local_addr().unwrap();
        let second = RtpUdpSocket::bind_reuse(first_addr, 2).unwrap();

        first.set_multicast_if_v4(Ipv4Addr::UNSPECIFIED).unwrap();
        second.set_multicast_if_v4(Ipv4Addr::UNSPECIFIED).unwrap();
    }

    #[test]
    fn simple_profile_recovers_dropped_udp_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let receiver_rtcp_addr = receiver.rtcp_local_addr().unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let sender_rtcp_addr = sender.rtcp_local_addr().unwrap();
        assert_eq!(receiver_addr.port() % 2, 0);
        assert_eq!(receiver_rtcp_addr.port(), receiver_addr.port() + 1);
        assert_eq!(sender_addr.port() % 2, 0);
        assert_eq!(sender_rtcp_addr.port(), sender_addr.port() + 1);

        let first = sender.build_payload(b"first", ntp, now);
        let _lost = sender.build_payload(b"lost", ntp, now);
        let third = sender.build_payload(b"third", ntp, now);
        sender.send_outbound(&first).unwrap();
        sender.send_outbound(&third).unwrap();

        let mut rx_buf = [0u8; 1500];
        let received_first = recv_payload_eventually(&mut receiver, &mut rx_buf);
        let received_third = recv_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received_first.payload, b"first");
        assert_eq!(received_third.payload, b"third");
        assert_eq!(received_third.newly_missing, vec![1]);

        receiver.send_feedback_to(sender_addr).unwrap();

        let mut feedback_buf = [0u8; 1500];
        let retries = recv_feedback_eventually(&mut sender, &mut feedback_buf);
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].sequence, 1);
        assert!(retries[0].retry);

        let recovered = recv_payload_eventually(&mut receiver, &mut rx_buf);
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    #[test]
    fn simple_profile_suppresses_and_expands_npd_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_null_packet_suppression();

        let payload = npd_payload();
        let sent = sender.send_payload(&payload, ntp, now).unwrap();
        assert!(sent.bytes.len() < payload.len() + 12);

        let mut rx_buf = [0u8; 1500];
        let received = recv_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received.payload, payload);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn simple_profile_receives_multicast_payload() {
        let flow_id = 0x1122_3344;
        let interface = Ipv4Addr::UNSPECIFIED;
        let mut receiver = SimpleMioReceiver::bind(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            flow_id,
            "rust",
            NackMode::Range,
        )
        .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let group = Ipv4Addr::new(239, 255, (port >> 8) as u8, port as u8);
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(group, port));
        receiver.join_multicast_v4(group, interface).unwrap();

        let mut sender = SimpleMioSender::connect(loopback_any(), multicast_addr, flow_id, 64)
            .or_else(|_| {
                SimpleMioSender::connect(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                    multicast_addr,
                    flow_id,
                    64,
                )
            })
            .unwrap();
        sender.set_multicast_loop_v4(true).unwrap();
        sender.set_multicast_ttl_v4(1).unwrap();

        for _ in 0..5 {
            sender
                .send_payload(
                    b"multicast",
                    ntp_from_unix_duration(Duration::from_secs(1)),
                    Instant::now(),
                )
                .unwrap();
            thread::sleep(Duration::from_millis(10));
        }

        let mut rx_buf = [0u8; 1500];
        let received = recv_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received.payload, b"multicast");

        receiver.leave_multicast_v4(group, interface).unwrap();
    }

    #[test]
    fn simple_profile_echo_updates_sender_rtt_over_udp() {
        let flow_id = 0x1122_3344;
        let request_ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let response_ntp =
            ntp_from_unix_duration(Duration::from_secs(1) + Duration::from_millis(7));
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();

        sender.send_echo_request_at(request_ntp).unwrap();
        let mut rx_buf = [0u8; 1500];
        recv_rtcp_response_eventually(&mut receiver, &mut rx_buf);

        let mut feedback_buf = [0u8; 1500];
        let retries = recv_feedback_eventually_at(&mut sender, &mut feedback_buf, response_ntp);
        assert!(retries.is_empty());
        assert_eq!(sender.stats().rtt_micros, Some(7_000));
    }

    #[test]
    fn main_profile_recovers_dropped_udp_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();

        let first = sender.build_payload(b"first", ntp, now);
        let _lost = sender.build_payload(b"lost", ntp, now);
        let third = sender.build_payload(b"third", ntp, now);
        sender.send_outbound(&first).unwrap();
        sender.send_outbound(&third).unwrap();

        let mut rx_buf = [0u8; 1500];
        let received_first = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        let received_third = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received_first.payload, b"first");
        assert_eq!(received_third.payload, b"third");
        assert_eq!(received_third.newly_missing, vec![1]);

        receiver.send_feedback_to(sender_addr).unwrap();

        let mut feedback_buf = [0u8; 1500];
        let retries = recv_main_feedback_eventually(&mut sender, &mut feedback_buf);
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].rtp_sequence, 1);
        assert!(retries[0].retry);

        let recovered = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    #[test]
    fn main_profile_recovers_encrypted_udp_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_tx_key(PskKey::new(256, b"secret").unwrap());
        receiver.set_rx_key(PskKey::receiver(256, b"secret").unwrap());
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.set_tx_key(PskKey::new(256, b"secret").unwrap());
        sender.set_rx_key(PskKey::receiver(256, b"secret").unwrap());
        let sender_addr = sender.local_addr().unwrap();

        let first = sender.build_payload(b"first", ntp, now);
        let _lost = sender.build_payload(b"lost", ntp, now);
        let third = sender.build_payload(b"third", ntp, now);
        assert_eq!(&first.bytes[..4], &[0x30, 0x48, 0x88, 0xb6]);
        sender.send_outbound(&first).unwrap();
        sender.send_outbound(&third).unwrap();

        let mut rx_buf = [0u8; 1500];
        let received_first = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        let received_third = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received_first.payload, b"first");
        assert_eq!(received_third.payload, b"third");
        assert_eq!(received_third.newly_missing, vec![1]);

        receiver.send_feedback_to(sender_addr).unwrap();

        let mut feedback_buf = [0u8; 1500];
        let retries = recv_main_feedback_eventually(&mut sender, &mut feedback_buf);
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].rtp_sequence, 1);

        let recovered = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert!(recovered.recovered);
        assert_eq!(recovered.payload, b"lost");
    }

    #[test]
    fn main_profile_multi_sender_duplicates_zero_weight_peers() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let rx_a = StdUdpSocket::bind(loopback_any()).unwrap();
        let rx_b = StdUdpSocket::bind(loopback_any()).unwrap();
        rx_a.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        rx_b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let mut sender = MainMioMultiSender::bind(loopback_any(), flow_id, 64).unwrap();
        sender.add_peer(rx_a.local_addr().unwrap(), 0);
        sender.add_peer(rx_b.local_addr().unwrap(), 0);

        let sent = sender
            .send_payload(b"duplicate", ntp, Instant::now())
            .unwrap();
        assert_eq!(sent.peers, vec![0, 1]);

        let mut buf_a = [0u8; 1500];
        let mut buf_b = [0u8; 1500];
        assert_eq!(recv_raw_main_payload(&rx_a, &mut buf_a), b"duplicate");
        assert_eq!(recv_raw_main_payload(&rx_b, &mut buf_b), b"duplicate");
    }

    #[test]
    fn main_profile_receiver_flags_bonded_duplicate_payload() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender = MainMioMultiSender::bind(loopback_any(), flow_id, 64).unwrap();
        sender.add_peer(receiver_addr, 0);
        sender.add_peer(receiver_addr, 0);

        let sent = sender
            .send_payload(b"bonded-duplicate", ntp, Instant::now())
            .unwrap();
        assert_eq!(sent.peers, vec![0, 1]);

        let mut rx_buf = [0u8; 1500];
        let first = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        let duplicate = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert!(!first.duplicate);
        assert!(duplicate.duplicate);
        assert_eq!(first.sequence, duplicate.sequence);
        assert_eq!(duplicate.payload, b"bonded-duplicate");
        assert_eq!(receiver.stats().duplicate_packets, 1);
        assert_eq!(receiver.stats().unique_received_packets(), 1);
    }

    #[test]
    fn main_profile_multi_sender_load_balances_positive_weights() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let rx_a = StdUdpSocket::bind(loopback_any()).unwrap();
        let rx_b = StdUdpSocket::bind(loopback_any()).unwrap();

        let mut sender = MainMioMultiSender::bind(loopback_any(), flow_id, 64).unwrap();
        sender.add_peer(rx_a.local_addr().unwrap(), 2);
        sender.add_peer(rx_b.local_addr().unwrap(), 1);

        let mut counts = [0usize; 2];
        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            let sent = sender.send_payload(payload, ntp, Instant::now()).unwrap();
            assert_eq!(sent.peers.len(), 1);
            counts[sent.peers[0]] += 1;
        }

        assert_eq!(counts, [2, 1]);
    }

    #[test]
    fn main_profile_multi_sender_isolates_recovery_by_peer() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let start = Instant::now();
        let rx_a = StdUdpSocket::bind(loopback_any()).unwrap();
        let rx_b = StdUdpSocket::bind(loopback_any()).unwrap();
        rx_a.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        rx_b.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        let mut sender = MainMioMultiSender::bind(loopback_any(), flow_id, 64).unwrap();
        let peer_a = sender.add_peer(rx_a.local_addr().unwrap(), 0);
        let peer_b = sender.add_peer(rx_b.local_addr().unwrap(), 0);
        sender.set_recovery_config(
            RecoveryConfig {
                length_min: Duration::from_secs(1),
                length_max: Duration::from_secs(1),
                max_retries: 1,
                max_bitrate: 100_000,
                ..RecoveryConfig::default()
            },
            CongestionControlMode::Off,
        );
        let sender_addr = sender.local_addr().unwrap();

        for payload in [b"zero".as_slice(), b"lost", b"two"] {
            sender.send_payload(payload, ntp, start).unwrap();
        }

        let packets_a = (0..3).map(|_| recv_raw_datagram(&rx_a)).collect::<Vec<_>>();
        let packets_b = (0..3).map(|_| recv_raw_datagram(&rx_b)).collect::<Vec<_>>();
        let mut receiver_a = MainReceiverCore::new(flow_id, "peer-a", NackMode::Range);
        let mut receiver_b = MainReceiverCore::new(flow_id, "peer-b", NackMode::Range);
        for (receiver, packets) in [(&mut receiver_a, &packets_a), (&mut receiver_b, &packets_b)] {
            receiver.accept_packet(&packets[0]).unwrap();
            let third = receiver.accept_packet(&packets[2]).unwrap();
            assert_eq!(third.newly_missing, vec![1]);
        }
        let feedback_a = receiver_a.build_feedback();
        let feedback_b = receiver_b.build_feedback();
        let mut feedback_buf = [0u8; 1500];

        rx_a.send_to(&feedback_a.bytes, sender_addr).unwrap();
        let retry_a = recv_multi_feedback_eventually(&mut sender, &mut feedback_buf);
        assert_eq!(retry_a.len(), 1);
        assert_eq!(retry_a[0].rtp_sequence, 1);
        assert_eq!(recv_raw_main_payload(&rx_a, &mut feedback_buf), b"lost");
        assert!(matches!(
            rx_b.recv_from(&mut feedback_buf),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                )
        ));

        rx_b.send_to(&feedback_b.bytes, sender_addr).unwrap();
        let retry_b = recv_multi_feedback_eventually(&mut sender, &mut feedback_buf);
        assert_eq!(retry_b.len(), 1);
        assert_eq!(retry_b[0].rtp_sequence, 1);
        assert_eq!(recv_raw_main_payload(&rx_b, &mut feedback_buf), b"lost");

        rx_a.send_to(&feedback_a.bytes, sender_addr).unwrap();
        assert!(recv_multi_feedback_eventually(&mut sender, &mut feedback_buf).is_empty());

        let stats_a = sender.peer_stats(peer_a).unwrap();
        let stats_b = sender.peer_stats(peer_b).unwrap();
        assert_eq!(stats_a.sent_packets, 3);
        assert_eq!(stats_b.sent_packets, 3);
        assert_eq!(stats_a.retransmitted_packets, 1);
        assert_eq!(stats_b.retransmitted_packets, 1);
        assert_eq!(stats_a.feedback_packets, 2);
        assert_eq!(stats_b.feedback_packets, 1);
        assert!(sender.peer_last_activity(peer_a).is_some());
        assert!(sender.peer_last_activity(peer_b).is_some());
    }

    #[test]
    fn main_profile_multi_sender_authenticates_each_peer_independently() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver_a =
            MainMioReceiver::bind(loopback_any(), flow_id, "peer-a", NackMode::Range).unwrap();
        let mut receiver_b =
            MainMioReceiver::bind(loopback_any(), flow_id, "peer-b", NackMode::Range).unwrap();
        for receiver in [&mut receiver_a, &mut receiver_b] {
            let mut store = SrpCredentialStore::new();
            store.stage_password("rist", b"multipath").unwrap();
            receiver.enable_srp_authenticator(store);
        }

        let mut sender = MainMioMultiSender::bind(loopback_any(), flow_id, 64).unwrap();
        let peer_a = sender.add_peer(receiver_a.local_addr().unwrap(), 0);
        let peer_b = sender.add_peer(receiver_b.local_addr().unwrap(), 0);
        sender.enable_srp_client("rist", b"multipath");
        let sender_addr = sender.local_addr().unwrap();
        let starts = sender.start_srp_authentication_all().unwrap();
        assert_eq!(
            starts.iter().map(|packet| packet.peer).collect::<Vec<_>>(),
            vec![peer_a, peer_b]
        );

        let mut sender_buf = [0u8; 2048];
        let mut receiver_buf = [0u8; 2048];
        drive_multi_srp_peer(
            &mut sender,
            &mut receiver_a,
            peer_a,
            sender_addr,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert_eq!(sender.peer_srp_authenticated(peer_a), Some(true));
        assert_eq!(sender.peer_srp_authenticated(peer_b), Some(false));
        assert!(!sender.srp_authenticated());

        let error = sender
            .send_payload(b"must-wait", ntp, Instant::now())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(sender.stats().sent_packets, 0);

        drive_multi_srp_peer(
            &mut sender,
            &mut receiver_b,
            peer_b,
            sender_addr,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert!(sender.srp_authenticated());

        let sent = sender
            .send_payload(b"authenticated-multipath", ntp, Instant::now())
            .unwrap();
        assert_eq!(sent.peers, vec![peer_a, peer_b]);
        for receiver in [&mut receiver_a, &mut receiver_b] {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match receiver.try_recv_event(&mut receiver_buf).unwrap() {
                    Some(MainReceiverEvent::Payload { payload, .. }) => {
                        assert_eq!(payload.payload, b"authenticated-multipath");
                        break;
                    }
                    Some(event) => panic!("unexpected Main receiver event: {event:?}"),
                    None => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for authenticated multipath payload"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }

    #[test]
    fn main_profile_refreshes_sender_activity_only_for_accepted_traffic() {
        let flow_id = 0x1122_3344;
        let peer = StdUdpSocket::bind(loopback_any()).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let mut sender = MainMioSender::connect(loopback_any(), peer_addr, flow_id, 64).unwrap();
        sender.set_session_config(MainSessionConfig {
            keepalive_interval: Duration::from_secs(1),
            session_timeout: Duration::ZERO,
        });
        let sender_addr = sender.local_addr().unwrap();
        let mut unknown = Vec::new();
        GreHeader {
            protocol_type: 0x1234,
            version: 1,
            key: None,
            sequence: Some(1),
        }
        .encode(&mut unknown);
        unknown.extend_from_slice(b"not accepted");
        peer.send_to(&unknown, sender_addr).unwrap();

        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match sender.try_recv_event(&mut buf).unwrap() {
                Some(MainSenderEvent::Unhandled { .. }) => break,
                Some(event) => panic!("unexpected Main sender event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for unknown control packet"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert!(!sender.poll_session(Instant::now()).timed_out);

        let mut peer_core = MainReceiverCore::new(flow_id, "peer", NackMode::Range);
        let keepalive =
            peer_core.build_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]));
        peer.send_to(&keepalive.bytes, sender_addr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match sender.try_recv_event(&mut buf).unwrap() {
                Some(MainSenderEvent::Keepalive { .. }) => break,
                Some(event) => panic!("unexpected Main sender event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for valid keepalive"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert!(sender.poll_session(Instant::now()).timed_out);
    }

    #[test]
    fn main_profile_rebinds_only_after_fresh_peer_authentication() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let now = Instant::now();
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        receiver.set_session_config(MainSessionConfig {
            keepalive_interval: Duration::from_secs(1),
            session_timeout: Duration::ZERO,
        });
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"rebind").unwrap();
        receiver.enable_srp_authenticator(store);
        let receiver_addr = receiver.local_addr().unwrap();

        let mut old_sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        old_sender.enable_srp_client("rist", b"rebind");
        let old_addr = old_sender.local_addr().unwrap();
        let mut sender_buf = [0u8; 2048];
        let mut receiver_buf = [0u8; 2048];
        old_sender.start_srp_authentication().unwrap();
        drive_main_srp_authentication(
            &mut old_sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );

        let first = old_sender.build_payload(b"zero", ntp, now);
        let _lost = old_sender.build_payload(b"lost", ntp, now);
        let third = old_sender.build_payload(b"two", ntp, now);
        old_sender.send_outbound(&first).unwrap();
        old_sender.send_outbound(&third).unwrap();
        recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(
            receiver.peer_missing_sequences(old_addr, flow_id),
            Some(vec![1])
        );

        let mut new_sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        new_sender.enable_srp_client("rist", b"rebind");
        let new_addr = new_sender.local_addr().unwrap();
        new_sender.start_srp_authentication().unwrap();
        drive_main_srp_authentication(
            &mut new_sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );

        assert_eq!(receiver.peer_count(), 1);
        assert_eq!(receiver.peer_authenticated(old_addr), None);
        assert_eq!(receiver.peer_authenticated(new_addr), Some(true));
        assert_eq!(
            receiver.peer_missing_sequences(new_addr, flow_id),
            Some(vec![1])
        );

        let stale = old_sender
            .send_payload(b"stale-session", ntp, Instant::now())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.try_recv_event(&mut receiver_buf).unwrap() {
                Some(MainReceiverEvent::Unhandled { from, .. }) if from == old_addr => break,
                Some(event) => panic!("unexpected Main receiver event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for stale-session rejection"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert_eq!(stale.rtp_sequence, 3);
        assert_eq!(
            receiver.peer_missing_sequences(new_addr, flow_id),
            Some(vec![1])
        );
    }

    #[test]
    fn main_profile_reauthenticates_a_restarted_peer_on_the_same_tuple() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"restart").unwrap();
        receiver.enable_srp_authenticator(store);
        let receiver_addr = receiver.local_addr().unwrap();

        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_srp_client("rist", b"restart");
        let sender_addr = sender.local_addr().unwrap();
        let mut sender_buf = [0u8; 2048];
        let mut receiver_buf = [0u8; 2048];
        sender.start_srp_authentication().unwrap();
        drive_main_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert_eq!(receiver.peer_authenticated(sender_addr), Some(true));
        drop(sender);

        let mut restarted =
            MainMioSender::connect(sender_addr, receiver_addr, flow_id, 64).unwrap();
        restarted.enable_srp_client("rist", b"restart");
        restarted.start_srp_authentication().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.try_recv_event(&mut receiver_buf).unwrap() {
                Some(MainReceiverEvent::Eapol { from, .. }) if from == sender_addr => break,
                Some(event) => panic!("unexpected Main receiver event: {event:?}"),
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for restarted peer"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert_eq!(receiver.peer_authenticated(sender_addr), Some(false));

        drive_main_srp_authentication(
            &mut restarted,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert_eq!(receiver.peer_count(), 1);
        assert_eq!(receiver.peer_authenticated(sender_addr), Some(true));
    }

    #[test]
    fn main_profile_caller_reauthenticates_after_listener_restart() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"listener-restart").unwrap();
        receiver.enable_srp_authenticator(store);

        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_srp_client("rist", b"listener-restart");
        sender.set_session_config(MainSessionConfig {
            keepalive_interval: Duration::from_millis(1),
            session_timeout: Duration::from_millis(5),
        });
        let mut sender_buf = [0u8; 2048];
        let mut receiver_buf = [0u8; 2048];
        sender.start_srp_authentication().unwrap();
        drive_main_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert!(sender.srp_authenticated());
        drop(receiver);

        let mut restarted =
            MainMioReceiver::bind(receiver_addr, flow_id, "receiver", NackMode::Range).unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"listener-restart").unwrap();
        restarted.enable_srp_authenticator(store);
        thread::sleep(Duration::from_millis(10));
        sender
            .poll_session_and_send_keepalive(
                Instant::now(),
                GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
            )
            .unwrap();
        assert!(!sender.srp_authenticated());

        drive_main_srp_authentication(
            &mut sender,
            &mut restarted,
            &mut sender_buf,
            &mut receiver_buf,
        );
        assert!(sender.srp_authenticated());
        assert_eq!(restarted.peer_count(), 1);
    }

    #[test]
    fn main_profile_srp_authenticates_before_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"mainprofile").unwrap();
        receiver.enable_srp_authenticator(store);
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_srp_client("rist", b"mainprofile");

        let err = sender.send_payload(b"too-early", ntp, now).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        sender.start_srp_authentication().unwrap();
        let mut sender_buf = [0u8; 1500];
        let mut receiver_buf = [0u8; 1500];
        drive_main_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );

        sender.send_payload(b"payload", ntp, now).unwrap();
        let received = recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(received.payload, b"payload");
    }

    #[test]
    fn main_profile_srp_reauthenticates_after_password_rollover() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let mut store = SrpCredentialStore::new();
        store.stage_password("rist", b"old-password").unwrap();
        receiver.enable_srp_authenticator(store);
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_srp_client("rist", b"old-password");

        sender.start_srp_authentication().unwrap();
        let mut sender_buf = [0u8; 1500];
        let mut receiver_buf = [0u8; 1500];
        drive_main_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );
        sender.send_payload(b"before-rollover", ntp, now).unwrap();
        let received = recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(received.payload, b"before-rollover");

        let generation = receiver
            .stage_srp_password("rist", b"new-password")
            .unwrap()
            .generation;
        receiver
            .retire_srp_generations_before("rist", generation)
            .unwrap();
        assert_eq!(receiver.current_srp_generation("rist"), Some(generation));
        sender.update_srp_client_password(b"new-password").unwrap();

        sender.start_srp_authentication().unwrap();
        drive_main_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );
        sender.send_payload(b"after-rollover", ntp, now).unwrap();
        let received = recv_main_payload_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(received.payload, b"after-rollover");
    }

    #[test]
    fn main_profile_suppresses_and_expands_npd_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.enable_null_packet_suppression();

        let payload = npd_payload();
        let sent = sender.send_payload(&payload, ntp, now).unwrap();
        assert!(sent.bytes.len() < payload.len() + 12);

        let mut rx_buf = [0u8; 1500];
        let received = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(received.payload, payload);
    }

    #[test]
    fn main_profile_sends_keepalive_over_udp() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();

        let sent = sender
            .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
            .unwrap();
        assert_eq!(sent.gre_sequence, 0);

        let mut rx_buf = [0u8; 1500];
        let keepalive = recv_keepalive_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(keepalive.sequence, Some(0));
        assert_eq!(keepalive.mac, [1, 2, 3, 4, 5, 6]);
        assert!(keepalive.supports_null_packet_deletion);
        assert!(keepalive.supports_reduced_overhead);
    }

    #[test]
    fn main_profile_session_timer_sends_due_keepalive_over_udp() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.set_session_config(MainSessionConfig {
            keepalive_interval: Duration::ZERO,
            session_timeout: Duration::from_millis(50),
        });

        let sent = sender
            .poll_session_and_send_keepalive(
                Instant::now(),
                GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
            )
            .unwrap();
        assert!(sent.poll.keepalive_due);
        assert_eq!(sent.keepalive.unwrap().gre_sequence, 0);

        let mut rx_buf = [0u8; 1500];
        let keepalive = recv_keepalive_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(keepalive.sequence, Some(0));
        assert_eq!(keepalive.mac, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn main_profile_sends_buffer_negotiation_over_udp() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();

        let sent = sender
            .send_buffer_negotiation(BufferNegotiation::session(1000, 250))
            .unwrap();
        assert_eq!(sent.gre_sequence, 0);

        let mut rx_buf = [0u8; 1500];
        let negotiation = recv_buffer_negotiation_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(negotiation.sequence, Some(0));
        assert_eq!(negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(negotiation.receiver_current_buffer_ms, 250);
    }

    #[test]
    fn main_profile_sends_encrypted_control_packets_over_udp() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_rx_key(PskKey::receiver(256, b"secret").unwrap());
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        sender.set_tx_key(PskKey::new(256, b"secret").unwrap());

        let sent = sender
            .send_keepalive(GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]))
            .unwrap();
        assert_eq!(&sent.bytes[..4], &[0x30, 0x48, 0x88, 0xb5]);

        let mut rx_buf = [0u8; 1500];
        let keepalive = recv_keepalive_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(keepalive.sequence, Some(0));
        assert_eq!(keepalive.mac, [1, 2, 3, 4, 5, 6]);

        let sent = sender
            .send_buffer_negotiation(BufferNegotiation::session(1000, 250))
            .unwrap();
        assert_eq!(&sent.bytes[..4], &[0x30, 0x50, 0xcc, 0xe0]);

        let negotiation = recv_buffer_negotiation_eventually(&mut receiver, &mut rx_buf);
        assert_eq!(negotiation.sequence, Some(1));
        assert_eq!(negotiation.sender_max_buffer_ms, 1000);
        assert_eq!(negotiation.receiver_current_buffer_ms, 250);
    }

    #[test]
    fn main_profile_sender_restart_keeps_send_loop_usable() {
        let sink = StdUdpSocket::bind(loopback_any()).unwrap();
        sink.set_nonblocking(true).unwrap();
        let peer = sink.local_addr().unwrap();
        let payload = ts_packet(0x0100, b"restart");
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));

        for iteration in 0..5 {
            let mut sender =
                MainMioSender::connect(loopback_any(), peer, 0x1122_3344 + iteration, 64).unwrap();

            for i in 0..1000 {
                sender.send_payload(&payload, ntp, Instant::now()).unwrap();
                if i % 50 == 0 {
                    drain_udp_sink(&sink);
                }
            }

            drop(sender);
            drain_udp_sink(&sink);
        }
    }

    fn npd_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&ts_packet(0x0100, b"first"));
        payload.extend_from_slice(&ts_packet(TS_NULL_PID, b""));
        payload.extend_from_slice(&ts_packet(0x0101, b"third"));
        payload
    }

    fn ts_packet(pid: u16, label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xff; TS_PACKET_SIZE];
        packet[0] = TS_SYNC_BYTE;
        packet[1..3].copy_from_slice(&pid.to_be_bytes());
        packet[3] = 0x10;
        packet[4..4 + label.len()].copy_from_slice(label);
        packet
    }

    fn drain_udp_sink(socket: &StdUdpSocket) {
        let mut buf = [0u8; 2048];
        loop {
            match socket.recv_from(&mut buf) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(err) => panic!("failed to drain UDP sink: {err}"),
            }
        }
    }

    fn recv_raw_main_payload(socket: &StdUdpSocket, buf: &mut [u8]) -> Vec<u8> {
        let (len, _) = socket.recv_from(buf).unwrap();
        let reduced = ReducedPacket::decode(&buf[..len]).unwrap();
        let rtp = RtpPacket::decode(reduced.payload).unwrap();
        rtp.payload.to_vec()
    }

    fn recv_raw_datagram(socket: &StdUdpSocket) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        buf[..len].to_vec()
    }

    fn recv_payload_eventually(
        receiver: &mut SimpleMioReceiver,
        buf: &mut [u8],
    ) -> ReceivedPayload {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((_from, payload)) = receiver.try_recv_payload(buf).unwrap() {
                return payload;
            }
            assert!(Instant::now() < deadline, "timed out waiting for payload");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_feedback_eventually(
        sender: &mut SimpleMioSender,
        buf: &mut [u8],
    ) -> Vec<OutboundPacket> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(retries) = sender.try_recv_feedback_and_retransmit(buf).unwrap() {
                return retries;
            }
            assert!(Instant::now() < deadline, "timed out waiting for feedback");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_feedback_eventually_at(
        sender: &mut SimpleMioSender,
        buf: &mut [u8],
        now_ntp: u64,
    ) -> Vec<OutboundPacket> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(retries) = sender
                .try_recv_feedback_and_retransmit_at(buf, now_ntp)
                .unwrap()
            {
                return retries;
            }
            assert!(Instant::now() < deadline, "timed out waiting for feedback");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_rtcp_response_eventually(receiver: &mut SimpleMioReceiver, buf: &mut [u8]) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(response_count) = receiver.try_recv_rtcp_and_respond(buf).unwrap() {
                assert_eq!(response_count, 1);
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for RTCP");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_main_payload_eventually(
        receiver: &mut MainMioReceiver,
        buf: &mut [u8],
    ) -> ReceivedPayload {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((_from, payload)) = receiver.try_recv_payload(buf).unwrap() {
                return payload;
            }
            assert!(Instant::now() < deadline, "timed out waiting for payload");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_main_feedback_eventually(
        sender: &mut MainMioSender,
        buf: &mut [u8],
    ) -> Vec<MainOutboundPacket> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(retries) = sender.try_recv_feedback_and_retransmit(buf).unwrap() {
                return retries;
            }
            assert!(Instant::now() < deadline, "timed out waiting for feedback");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_multi_feedback_eventually(
        sender: &mut MainMioMultiSender,
        buf: &mut [u8],
    ) -> Vec<MainOutboundPacket> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(retries) = sender.try_recv_feedback_and_retransmit(buf).unwrap() {
                return retries;
            }
            assert!(Instant::now() < deadline, "timed out waiting for feedback");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn drive_multi_srp_peer(
        sender: &mut MainMioMultiSender,
        receiver: &mut MainMioReceiver,
        peer: usize,
        sender_addr: SocketAddr,
        sender_buf: &mut [u8],
        receiver_buf: &mut [u8],
    ) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while sender.peer_srp_authenticated(peer) != Some(true)
            || receiver.peer_authenticated(sender_addr) != Some(true)
        {
            receiver.try_recv_event(receiver_buf).unwrap();
            sender.try_recv_event(sender_buf).unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for multipath peer SRP authentication"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn drive_main_srp_authentication(
        sender: &mut MainMioSender,
        receiver: &mut MainMioReceiver,
        sender_buf: &mut [u8],
        receiver_buf: &mut [u8],
    ) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !sender.srp_authenticated() || !receiver.srp_authenticated() {
            receiver.try_recv_eapol_and_respond(receiver_buf).unwrap();
            sender.try_recv_eapol_and_respond(sender_buf).unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for SRP authentication"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    struct KeepaliveSummary {
        sequence: Option<u32>,
        mac: [u8; 6],
        supports_null_packet_deletion: bool,
        supports_reduced_overhead: bool,
    }

    struct BufferNegotiationSummary {
        sequence: Option<u32>,
        sender_max_buffer_ms: u16,
        receiver_current_buffer_ms: u16,
    }

    fn recv_keepalive_eventually(
        receiver: &mut MainMioReceiver,
        buf: &mut [u8],
    ) -> KeepaliveSummary {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((_from, packet)) = receiver.try_recv_keepalive(buf).unwrap() {
                return KeepaliveSummary {
                    sequence: packet.gre.sequence,
                    mac: packet.keepalive.mac,
                    supports_null_packet_deletion: packet.keepalive.supports_null_packet_deletion(),
                    supports_reduced_overhead: packet.keepalive.supports_reduced_overhead(),
                };
            }
            assert!(Instant::now() < deadline, "timed out waiting for keepalive");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_buffer_negotiation_eventually(
        receiver: &mut MainMioReceiver,
        buf: &mut [u8],
    ) -> BufferNegotiationSummary {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((_from, packet)) = receiver.try_recv_buffer_negotiation(buf).unwrap() {
                return BufferNegotiationSummary {
                    sequence: packet.gre.sequence,
                    sender_max_buffer_ms: packet.negotiation.sender_max_buffer_ms,
                    receiver_current_buffer_ms: packet.negotiation.receiver_current_buffer_ms,
                };
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for buffer negotiation"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}
