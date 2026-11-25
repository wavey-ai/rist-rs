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
    OwnedOobPacket, ReducedPacket,
};
use rist_core::packet::rtp::{encode_packet, RtpHeader, RtpPacket};
use rist_core::time::ntp_now;
use rist_core::{
    packet::rtcp::NackMode, CongestionControlMode, FeedbackOutcome, MainControlPacket,
    MainOutboundPacket, MainPacket, MainPacketMeta, MainReceiverCore, MainReceiverFeedback,
    MainSenderCore, MainSenderPeerState, MainSessionConfig, MainSessionPoll, MainSessionTimers,
    OutboundPacket, PeerSelection, ReceivedPayload, ReceiverStats, RecoveryConfig, RecoveryTuning,
    SenderStats, SimpleReceiverCore, SimpleSenderCore, SrpCredentialStore, WeightedPeerSelector,
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::{Duration, Instant};

const PENDING_SEND_CAPACITY: usize = 256;
pub const TARGET_SOCKET_BUFFER_SIZE: usize = 8 * 1024 * 1024;
pub const MINIMUM_SOCKET_BUFFER_SIZE: usize = 1024 * 1024 / 5;
pub const MAX_RIST_DATAGRAM_SIZE: usize = 10_000;
const SAFE_RECEIVE_CAPACITY: usize = MAX_RIST_DATAGRAM_SIZE + 1;
pub const DEFAULT_MAIN_EVENT_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_MAIN_PEER_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkInterface {
    Default,
    Address(IpAddr),
    Index(u32),
    Name(String),
}

impl NetworkInterface {
    pub fn from_miface(value: &str) -> Self {
        value
            .parse()
            .map(Self::Address)
            .unwrap_or_else(|_| Self::Name(value.to_string()))
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolvedNetworkInterface {
    index: u32,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

pub fn network_interface_index(interface: &NetworkInterface) -> io::Result<u32> {
    Ok(resolve_network_interface(interface)?.index)
}

pub fn network_interface_address(interface: &NetworkInterface, ipv4: bool) -> io::Result<IpAddr> {
    let resolved = resolve_network_interface(interface)?;
    if ipv4 {
        if resolved.ipv4.is_unspecified() && !matches!(interface, NetworkInterface::Default) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "network interface has no IPv4 address",
            ));
        }
        Ok(IpAddr::V4(resolved.ipv4))
    } else {
        resolved.ipv6.map(IpAddr::V6).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "network interface has no IPv6 address",
            )
        })
    }
}

struct PendingDatagram {
    bytes: Vec<u8>,
    peer: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketBufferSizes {
    pub receive: usize,
    pub send: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimpleSocketBufferSizes {
    pub rtp: SocketBufferSizes,
    pub rtcp: SocketBufferSizes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruncatedDatagram {
    pub peer: SocketAddr,
    pub datagram_size: usize,
    pub buffer_capacity: usize,
}

impl fmt::Display for TruncatedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-byte UDP datagram from {} exceeded the {}-byte receive buffer",
            self.datagram_size, self.peer, self.buffer_capacity
        )
    }
}

impl std::error::Error for TruncatedDatagram {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OversizedDatagram {
    pub peer: Option<SocketAddr>,
    pub observed_size: Option<usize>,
}

impl fmt::Display for OversizedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.peer, self.observed_size) {
            (Some(peer), Some(size)) => write!(
                formatter,
                "{size}-byte UDP datagram from {peer} exceeded the {MAX_RIST_DATAGRAM_SIZE}-byte RIST limit"
            ),
            _ => write!(
                formatter,
                "UDP datagram exceeded the {MAX_RIST_DATAGRAM_SIZE}-byte RIST limit"
            ),
        }
    }
}

impl std::error::Error for OversizedDatagram {}

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
    receive_scratch: Vec<u8>,
}

impl RtpUdpSocket {
    pub fn bind(local: SocketAddr, ssrc: u32) -> io::Result<Self> {
        Self::from_socket(UdpSocket::bind(local)?, None, ssrc)
    }

    pub fn bind_reuse(local: SocketAddr, ssrc: u32) -> io::Result<Self> {
        Self::from_socket(bind_reuse_udp(local)?, None, ssrc)
    }

    pub fn connect(local: SocketAddr, peer: SocketAddr, ssrc: u32) -> io::Result<Self> {
        ensure_same_address_family(local, peer)?;
        let socket = UdpSocket::bind(local)?;
        socket.connect(peer)?;
        Self::from_socket(socket, Some(peer), ssrc)
    }

    /// The SSRC's least significant bit marks RIST retransmissions, so it
    /// is cleared: with an odd SSRC every packet would read as a repair.
    fn from_socket(socket: UdpSocket, peer: Option<SocketAddr>, ssrc: u32) -> io::Result<Self> {
        let socket = Self {
            socket,
            peer,
            next_sequence: 0,
            ssrc: ssrc & !1,
            receive_scratch: vec![0u8; SAFE_RECEIVE_CAPACITY],
        };
        socket.configure_optimal_socket_buffers()?;
        Ok(socket)
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

    /// The peer this socket is connected to, if it was made with
    /// [`Self::connect`].
    pub fn connected_peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Connects a bound socket to `peer` (see [`Self::connect`]).
    fn connect_to(&mut self, peer: SocketAddr) -> io::Result<()> {
        self.socket.connect(peer)?;
        self.peer = Some(peer);
        Ok(())
    }

    /// Sends `head` and `body` as one datagram without joining them first
    /// (one `sendmsg` with two parts on Unix). `peer` `None` sends to the
    /// connected peer. A connected socket reports an ICMP error an earlier
    /// datagram drew (`is_reported_icmp_error`) on a later call,
    /// which then sends nothing; that datagram was not refused, so the send
    /// is tried once more.
    pub fn send_parts_to(
        &mut self,
        peer: Option<SocketAddr>,
        head: &[u8],
        body: &[u8],
    ) -> io::Result<usize> {
        match self.send_parts_once(peer, head, body) {
            Err(error) if is_reported_icmp_error(&error) => self.send_parts_once(peer, head, body),
            result => result,
        }
        .map_err(normalize_udp_send_error)
    }

    #[cfg(unix)]
    fn send_parts_once(
        &mut self,
        peer: Option<SocketAddr>,
        head: &[u8],
        body: &[u8],
    ) -> io::Result<usize> {
        use nix::sys::socket::{sendmsg, MsgFlags, SockaddrStorage};
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;
        let parts = [IoSlice::new(head), IoSlice::new(body)];
        let address = peer.map(SockaddrStorage::from);
        sendmsg(
            self.socket.as_raw_fd(),
            &parts,
            &[],
            MsgFlags::empty(),
            address.as_ref(),
        )
        .map_err(nix_to_io)
    }

    #[cfg(not(unix))]
    fn send_parts_once(
        &mut self,
        peer: Option<SocketAddr>,
        head: &[u8],
        body: &[u8],
    ) -> io::Result<usize> {
        let mut datagram = Vec::with_capacity(head.len() + body.len());
        datagram.extend_from_slice(head);
        datagram.extend_from_slice(body);
        match peer {
            Some(peer) => self.socket.send_to(&datagram, peer),
            None => self.socket.send(&datagram),
        }
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
        SockRef::from(&self.socket).set_multicast_loop_v6(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
    }

    pub fn set_multicast_hops_v6(&self, hops: u32) -> io::Result<()> {
        SockRef::from(&self.socket).set_multicast_hops_v6(hops)
    }

    pub fn set_multicast_if_v4(&self, interface: Ipv4Addr) -> io::Result<()> {
        SockRef::from(&self.socket).set_multicast_if_v4(&interface)
    }

    pub fn set_multicast_if_v6(&self, interface: u32) -> io::Result<()> {
        SockRef::from(&self.socket).set_multicast_if_v6(interface)
    }

    pub fn set_multicast_interface(&self, interface: &NetworkInterface) -> io::Result<()> {
        let resolved = resolve_network_interface(interface)?;
        if self.local_addr()?.is_ipv4() {
            self.set_multicast_if_v4(resolved.ipv4)
        } else {
            self.set_multicast_if_v6(resolved.index)
        }
    }

    pub fn socket_buffer_sizes(&self) -> io::Result<SocketBufferSizes> {
        let socket = SockRef::from(&self.socket);
        Ok(SocketBufferSizes {
            receive: socket.recv_buffer_size()?,
            send: socket.send_buffer_size()?,
        })
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SocketBufferSizes> {
        validate_socket_buffer_size(receive)?;
        validate_socket_buffer_size(send)?;
        let socket = SockRef::from(&self.socket);
        socket.set_recv_buffer_size(receive)?;
        socket.set_send_buffer_size(send)?;
        self.socket_buffer_sizes()
    }

    pub fn configure_optimal_socket_buffers(&self) -> io::Result<SocketBufferSizes> {
        let socket = SockRef::from(&self.socket);
        configure_optimal_socket_buffer(
            || socket.recv_buffer_size(),
            |size| socket.set_recv_buffer_size(size),
            "receive",
        )?;
        configure_optimal_socket_buffer(
            || socket.send_buffer_size(),
            |size| socket.set_send_buffer_size(size),
            "send",
        )?;
        self.socket_buffer_sizes()
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(&multiaddr, &interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.leave_multicast_v4(&multiaddr, &interface)
    }

    pub fn join_ssm_v4(
        &self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> io::Result<()> {
        validate_ssm_v4(source, group)?;
        SockRef::from(&self.socket).join_ssm_v4(&source, &group, &interface)
    }

    pub fn leave_ssm_v4(
        &self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> io::Result<()> {
        validate_ssm_v4(source, group)?;
        SockRef::from(&self.socket).leave_ssm_v4(&source, &group, &interface)
    }

    pub fn join_multicast_v6(&self, multiaddr: Ipv6Addr, interface: u32) -> io::Result<()> {
        if !multiaddr.is_multicast() {
            return Err(invalid_multicast_group(IpAddr::V6(multiaddr)));
        }
        self.socket.join_multicast_v6(&multiaddr, interface)
    }

    pub fn leave_multicast_v6(&self, multiaddr: Ipv6Addr, interface: u32) -> io::Result<()> {
        if !multiaddr.is_multicast() {
            return Err(invalid_multicast_group(IpAddr::V6(multiaddr)));
        }
        self.socket.leave_multicast_v6(&multiaddr, interface)
    }

    pub fn join_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        let resolved = resolve_network_interface(interface)?;
        match (group, source) {
            (IpAddr::V4(group), Some(source)) => self.join_ssm_v4(source, group, resolved.ipv4),
            (IpAddr::V4(group), None) if group.is_multicast() => {
                self.join_multicast_v4(group, resolved.ipv4)
            }
            (IpAddr::V4(group), None) => Err(invalid_multicast_group(IpAddr::V4(group))),
            (IpAddr::V6(group), None) => self.join_multicast_v6(group, resolved.index),
            (IpAddr::V6(_), Some(_)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 source-specific multicast is not supported by current librist",
            )),
        }
    }

    pub fn leave_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        let resolved = resolve_network_interface(interface)?;
        match (group, source) {
            (IpAddr::V4(group), Some(source)) => self.leave_ssm_v4(source, group, resolved.ipv4),
            (IpAddr::V4(group), None) if group.is_multicast() => {
                self.leave_multicast_v4(group, resolved.ipv4)
            }
            (IpAddr::V4(group), None) => Err(invalid_multicast_group(IpAddr::V4(group))),
            (IpAddr::V6(group), None) => self.leave_multicast_v6(group, resolved.index),
            (IpAddr::V6(_), Some(_)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 source-specific multicast is not supported by current librist",
            )),
        }
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
        let received = match self.recv_datagram_len(buf) {
            // A connected socket reports an ICMP error for an earlier send
            // on the next call; it says nothing about what is queued.
            Err(error) if self.peer.is_some() && is_reported_icmp_error(&error) => {
                self.recv_datagram_len(buf)
            }
            result => result,
        }?;
        Ok(received.map(|(from, len)| (from, &buf[..len])))
    }

    fn recv_datagram_len(&mut self, buf: &mut [u8]) -> io::Result<Option<(SocketAddr, usize)>> {
        if buf.len() >= SAFE_RECEIVE_CAPACITY {
            return match self.socket.recv_from(buf) {
                Ok((len, from)) if len > MAX_RIST_DATAGRAM_SIZE => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    OversizedDatagram {
                        peer: Some(from),
                        observed_size: Some(len),
                    },
                )),
                Ok((len, from)) => Ok(Some((from, len))),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
                #[cfg(windows)]
                Err(err) if err.raw_os_error() == Some(10040) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    OversizedDatagram {
                        peer: None,
                        observed_size: None,
                    },
                )),
                Err(err) => Err(err),
            };
        }

        match self.socket.recv_from(&mut self.receive_scratch) {
            Ok((len, from)) if len > MAX_RIST_DATAGRAM_SIZE => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                OversizedDatagram {
                    peer: Some(from),
                    observed_size: Some(len),
                },
            )),
            Ok((len, from)) if len > buf.len() => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                TruncatedDatagram {
                    peer: from,
                    datagram_size: len,
                    buffer_capacity: buf.len(),
                },
            )),
            Ok((len, from)) => {
                buf[..len].copy_from_slice(&self.receive_scratch[..len]);
                Ok(Some((from, len)))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            #[cfg(windows)]
            Err(err) if err.raw_os_error() == Some(10040) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                OversizedDatagram {
                    peer: None,
                    observed_size: None,
                },
            )),
            Err(err) => Err(err),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

fn validate_socket_buffer_size(size: usize) -> io::Result<()> {
    if !(MINIMUM_SOCKET_BUFFER_SIZE..=i32::MAX as usize).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket buffer size must be between {MINIMUM_SOCKET_BUFFER_SIZE} and i32::MAX bytes"
            ),
        ));
    }
    Ok(())
}

fn configure_optimal_socket_buffer(
    get: impl Fn() -> io::Result<usize>,
    set: impl Fn(usize) -> io::Result<()>,
    direction: &str,
) -> io::Result<usize> {
    let mut size = get()?;
    if size < TARGET_SOCKET_BUFFER_SIZE {
        let _ = set(TARGET_SOCKET_BUFFER_SIZE);
        size = get()?;
    }
    if size < MINIMUM_SOCKET_BUFFER_SIZE {
        set(MINIMUM_SOCKET_BUFFER_SIZE)?;
        size = get()?;
    }
    if size < MINIMUM_SOCKET_BUFFER_SIZE {
        return Err(io::Error::other(format!(
            "UDP {direction} buffer is {size} bytes; at least {MINIMUM_SOCKET_BUFFER_SIZE} bytes are required"
        )));
    }
    Ok(size)
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

fn ensure_same_address_family(local: SocketAddr, peer: SocketAddr) -> io::Result<()> {
    if local.is_ipv4() == peer.is_ipv4() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("local address {local} and peer address {peer} use different IP families"),
    ))
}

fn invalid_multicast_group(group: IpAddr) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{group} is not a multicast group"),
    )
}

fn validate_ssm_v4(source: Ipv4Addr, group: Ipv4Addr) -> io::Result<()> {
    if !group.is_multicast() {
        return Err(invalid_multicast_group(IpAddr::V4(group)));
    }
    if source.is_unspecified() || source.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{source} is not a valid unicast multicast source"),
        ));
    }
    Ok(())
}

fn resolve_network_interface(interface: &NetworkInterface) -> io::Result<ResolvedNetworkInterface> {
    match interface {
        NetworkInterface::Default => Ok(ResolvedNetworkInterface {
            index: 0,
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Some(Ipv6Addr::UNSPECIFIED),
        }),
        NetworkInterface::Address(IpAddr::V4(ipv4)) => Ok(ResolvedNetworkInterface {
            index: interface_index_for_address(IpAddr::V4(*ipv4))?.unwrap_or(0),
            ipv4: *ipv4,
            ipv6: None,
        }),
        NetworkInterface::Address(IpAddr::V6(ipv6)) => Ok(ResolvedNetworkInterface {
            index: interface_index_for_address(IpAddr::V6(*ipv6))?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no network interface owns IPv6 address {ipv6}"),
                )
            })?,
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Some(*ipv6),
        }),
        NetworkInterface::Index(index) => {
            let ipv4 = interface_ipv4_for_index(*index)?.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let ipv6 = interface_ipv6_for_index(*index)?;
            Ok(ResolvedNetworkInterface {
                index: *index,
                ipv4,
                ipv6,
            })
        }
        NetworkInterface::Name(name) => {
            let index = interface_index_for_name(name)?;
            let ipv4 = interface_ipv4_for_name(name)?.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let ipv6 = interface_ipv6_for_name(name)?;
            Ok(ResolvedNetworkInterface { index, ipv4, ipv6 })
        }
    }
}

#[cfg(unix)]
fn interface_index_for_name(name: &str) -> io::Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(nix_to_io)
}

#[cfg(not(unix))]
fn interface_index_for_name(name: &str) -> io::Result<u32> {
    name.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "this platform requires a numeric multicast interface index",
        )
    })
}

#[cfg(unix)]
fn interface_ipv4_for_name(name: &str) -> io::Result<Option<Ipv4Addr>> {
    let addresses = nix::ifaddrs::getifaddrs().map_err(nix_to_io)?;
    Ok(addresses
        .filter(|address| address.interface_name == name)
        .filter_map(|address| address.address)
        .find_map(|address| address.as_sockaddr_in().map(|address| address.ip())))
}

#[cfg(not(unix))]
fn interface_ipv4_for_name(_name: &str) -> io::Result<Option<Ipv4Addr>> {
    Ok(None)
}

#[cfg(unix)]
fn interface_ipv6_for_name(name: &str) -> io::Result<Option<Ipv6Addr>> {
    let addresses = nix::ifaddrs::getifaddrs().map_err(nix_to_io)?;
    Ok(addresses
        .filter(|address| address.interface_name == name)
        .filter_map(|address| address.address)
        .find_map(|address| address.as_sockaddr_in6().map(|address| address.ip())))
}

#[cfg(not(unix))]
fn interface_ipv6_for_name(_name: &str) -> io::Result<Option<Ipv6Addr>> {
    Ok(None)
}

#[cfg(unix)]
fn interface_ipv4_for_index(index: u32) -> io::Result<Option<Ipv4Addr>> {
    let name = nix::net::if_::if_indextoname(index)
        .map_err(nix_to_io)?
        .to_string_lossy()
        .into_owned();
    interface_ipv4_for_name(&name)
}

#[cfg(not(unix))]
fn interface_ipv4_for_index(_index: u32) -> io::Result<Option<Ipv4Addr>> {
    Ok(None)
}

#[cfg(unix)]
fn interface_ipv6_for_index(index: u32) -> io::Result<Option<Ipv6Addr>> {
    let name = nix::net::if_::if_indextoname(index)
        .map_err(nix_to_io)?
        .to_string_lossy()
        .into_owned();
    interface_ipv6_for_name(&name)
}

#[cfg(not(unix))]
fn interface_ipv6_for_index(_index: u32) -> io::Result<Option<Ipv6Addr>> {
    Ok(None)
}

#[cfg(unix)]
fn interface_index_for_address(address: IpAddr) -> io::Result<Option<u32>> {
    let addresses = nix::ifaddrs::getifaddrs().map_err(nix_to_io)?;
    for interface in addresses {
        let matches = match (address, interface.address) {
            (IpAddr::V4(expected), Some(actual)) => actual
                .as_sockaddr_in()
                .is_some_and(|actual| actual.ip() == expected),
            (IpAddr::V6(expected), Some(actual)) => actual
                .as_sockaddr_in6()
                .is_some_and(|actual| actual.ip() == expected),
            _ => false,
        };
        if matches {
            return interface_index_for_name(&interface.interface_name).map(Some);
        }
    }
    Ok(None)
}

#[cfg(not(unix))]
fn interface_index_for_address(_address: IpAddr) -> io::Result<Option<u32>> {
    Ok(None)
}

#[cfg(unix)]
fn nix_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
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

/// Errors a connected UDP socket returns, on the next send or receive, for
/// an ICMP error an earlier datagram drew (Linux reports hard ICMP errors
/// only to connected sockets): port unreachable (`ECONNREFUSED`), host or
/// administratively prohibited (`EHOSTUNREACH`), network unknown
/// (`ENETUNREACH`), host unknown (`EHOSTDOWN`), protocol unreachable
/// (`ENOPROTOOPT`) and source route failed (`EOPNOTSUPP`). The call that
/// returns one did nothing else.
fn is_reported_icmp_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::ConnectionRefused {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(
                libc::ECONNREFUSED
                    | libc::EHOSTUNREACH
                    | libc::ENETUNREACH
                    | libc::EHOSTDOWN
                    | libc::ENOPROTOOPT
                    | libc::EOPNOTSUPP
            )
        )
    }
    #[cfg(not(unix))]
    {
        false
    }
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

/// Sends a datagram at once when nothing is queued ahead of it (FIFO), or
/// queues it, joined into a reused buffer, when the socket would block. A
/// datagram to the socket's connected peer goes without an address. A
/// connected peer that is not listening drops it, as the path would.
fn send_or_queue(
    socket: &mut RtpUdpSocket,
    pending: &mut VecDeque<PendingDatagram>,
    spare: &mut Vec<Vec<u8>>,
    peer: SocketAddr,
    head: &[u8],
    body: &[u8],
) -> io::Result<()> {
    if pending.is_empty() {
        match send_parts(socket, peer, head, body) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    if pending.len() >= PENDING_SEND_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "RIST pending-send queue is full",
        ));
    }
    queue_datagram(pending, spare, peer, head, body);
    Ok(())
}

fn send_parts(
    socket: &mut RtpUdpSocket,
    peer: SocketAddr,
    head: &[u8],
    body: &[u8],
) -> io::Result<()> {
    let connected = socket.connected_peer() == Some(peer);
    let target = if connected { None } else { Some(peer) };
    match socket.send_parts_to(target, head, body) {
        Ok(len) if len == head.len() + body.len() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP send accepted a partial datagram",
        )),
        // Reported again on the retry: the path drops it, as it would
        // have dropped it on an unconnected socket, which never hears.
        Err(error) if connected && is_reported_icmp_error(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn queue_datagram(
    pending: &mut VecDeque<PendingDatagram>,
    spare: &mut Vec<Vec<u8>>,
    peer: SocketAddr,
    head: &[u8],
    body: &[u8],
) {
    let mut bytes = spare.pop().unwrap_or_default();
    bytes.clear();
    bytes.extend_from_slice(head);
    bytes.extend_from_slice(body);
    pending.push_back(PendingDatagram { bytes, peer });
}

/// Sends queued datagrams in FIFO order until the socket would block; the
/// buffers sent are kept for reuse.
fn flush_queue(
    socket: &mut RtpUdpSocket,
    pending: &mut VecDeque<PendingDatagram>,
    spare: &mut Vec<Vec<u8>>,
) -> io::Result<usize> {
    let mut sent = 0;
    while let Some(packet) = pending.front() {
        match send_parts(socket, packet.peer, &packet.bytes, &[]) {
            Ok(()) => {
                let packet = pending.pop_front().expect("front was checked");
                if spare.len() < PENDING_SEND_CAPACITY {
                    spare.push(packet.bytes);
                }
                sent += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(sent)
}

pub struct SimpleMioSender {
    rtp_socket: RtpUdpSocket,
    rtcp_socket: RtpUdpSocket,
    core: SimpleSenderCore,
    peer: Option<SocketAddr>,
    pending: VecDeque<PendingDatagram>,
    rtcp_pending: VecDeque<PendingDatagram>,
    spare: Vec<Vec<u8>>,
    /// When the SR/echo timer is next due (see [`MainMioSender`]).
    next_timer_at: Option<Instant>,
    /// Feedback served from inside the send path (see
    /// [`INLINE_SERVICE_EVERY`]).
    inline: InlineService,
}

/// Readiness of a Simple sender covers both its sockets under one token
/// (feedback arrives on the RTCP port). Sleep until the
/// [`SimpleMioSender::service`] deadline and call it on wakeup.
impl Source for SimpleMioSender {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.rtp_socket.register(registry, token, interests)?;
        self.rtcp_socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.rtp_socket.reregister(registry, token, interests)?;
        self.rtcp_socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.rtp_socket.deregister(registry)?;
        self.rtcp_socket.deregister(registry)
    }
}

impl SimpleMioSender {
    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        ssrc: u32,
        history_packets: usize,
    ) -> io::Result<Self> {
        ensure_same_address_family(local, peer)?;
        simple_rtcp_addr(peer)?;
        let (mut rtp_socket, rtcp_socket) = bind_simple_pair(local, ssrc, false)?;
        // The data socket only sends, to this one peer: connected, each send
        // skips the route lookup. Feedback arrives on the RTCP socket.
        rtp_socket.connect_to(peer)?;
        Ok(Self::with_sockets(
            rtp_socket,
            rtcp_socket,
            ssrc,
            history_packets,
            Some(peer),
        ))
    }

    pub fn listen(local: SocketAddr, ssrc: u32, history_packets: usize) -> io::Result<Self> {
        let (rtp_socket, rtcp_socket) = bind_simple_pair(local, ssrc, false)?;
        Ok(Self::with_sockets(
            rtp_socket,
            rtcp_socket,
            ssrc,
            history_packets,
            None,
        ))
    }

    fn with_sockets(
        rtp_socket: RtpUdpSocket,
        rtcp_socket: RtpUdpSocket,
        ssrc: u32,
        history_packets: usize,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            rtp_socket,
            rtcp_socket,
            core: SimpleSenderCore::new(ssrc, history_packets),
            peer,
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
            rtcp_pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
            spare: Vec::new(),
            next_timer_at: None,
            inline: InlineService::default(),
        }
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

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.core.set_recovery_tuning(tuning);
    }

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn send_outbound(&mut self, packet: &OutboundPacket) -> io::Result<usize> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.flush_pending()?;
        send_or_queue(
            &mut self.rtp_socket,
            &mut self.pending,
            &mut self.spare,
            peer,
            &packet.bytes,
            &[],
        )?;
        Ok(packet.bytes.len())
    }

    /// Sends one payload and returns the packet sent. Also sends the SR and
    /// echo request when due (see [`MainMioSender::send_payload`]). Use
    /// [`Self::send_payload_meta`] when the bytes are not needed.
    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<OutboundPacket> {
        let mut bytes = Vec::new();
        let sequence = self.send_payload_parts(payload, ntp_timestamp, now, |rtp| {
            bytes = rtp.to_vec();
        })?;
        Ok(OutboundPacket {
            sequence,
            retry: false,
            bytes,
        })
    }

    /// [`Self::send_payload`] without the bytes: sent straight from the
    /// history slot it was encoded into. Returns the RTP sequence.
    pub fn send_payload_meta(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<u32> {
        self.send_payload_parts(payload, ntp_timestamp, now, |_| {})
    }

    fn send_payload_parts(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
        observe: impl FnOnce(&[u8]),
    ) -> io::Result<u32> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.ensure_pending_capacity()?;
        if !self.pending.is_empty() {
            self.flush_pending()?;
        }
        let Self {
            core,
            rtp_socket,
            pending,
            spare,
            ..
        } = self;
        let sequence = core.send_payload_with(payload, ntp_timestamp, now, |sequence, rtp| {
            observe(rtp);
            send_or_queue(rtp_socket, pending, spare, peer, rtp, &[]).map(|()| sequence)
        })?;
        if self.next_timer_at.map_or(true, |at| now >= at) {
            if let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) {
                let _ = self.send_rtcp(&packet);
            }
            self.next_timer_at = Some(
                self.core
                    .next_rtcp_at()
                    .unwrap_or(now + std::time::Duration::from_millis(100)),
            );
        }
        if self.inline.due() {
            self.serve_inline(now);
        }
        Ok(sequence)
    }

    /// The send path's own feedback service, as
    /// [`MainMioSender`]'s: up to 64 waiting feedback datagrams served
    /// (their retransmissions are not reported), then due repairs.
    fn serve_inline(&mut self, now: Instant) {
        let mut buf = self.inline.take_buf();
        let mut drained = false;
        for _ in 0..INLINE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY {
                break;
            }
            match self.service_read(&mut buf) {
                Ok(ServiceRead::Read) => {}
                Ok(ServiceRead::Drained) => {
                    drained = true;
                    break;
                }
                Err(_) => break,
            }
        }
        self.inline.buf = buf;
        if !drained {
            self.inline.wake(now);
        }
        let _ = self.poll_repairs_and_send(now);
    }

    /// The Simple-profile [`MainMioSender::service`]: flushes the queues,
    /// serves feedback until the RTCP socket is drained (at most 512
    /// datagrams; feedback from another address is read and ignored),
    /// sends the SR/echo request and due repairs, and returns when to call
    /// it again (`now` when it stopped at the read limit).
    pub fn service(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
        buf: &mut [u8],
    ) -> io::Result<Option<Instant>> {
        self.inline.wake_at = None;
        self.inline.sends = 0;
        self.flush_pending()?;
        let mut more_to_read = true;
        for _ in 0..SERVICE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY
                || self.service_read(buf)? == ServiceRead::Drained
            {
                more_to_read = false;
                break;
            }
        }
        if self.peer.is_some() {
            match self.poll_rtcp_and_send(now, ntp_timestamp) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        self.next_timer_at = self.core.next_rtcp_at();
        Ok(service_deadline(
            now,
            self.next_timeout(),
            more_to_read,
            !(self.pending.is_empty() && self.rtcp_pending.is_empty()),
        ))
    }

    /// One read of the `service` loop.
    fn service_read(&mut self, buf: &mut [u8]) -> io::Result<ServiceRead> {
        let (from, feedback) = match self.rtcp_socket.recv_datagram(buf) {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(ServiceRead::Drained),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return Ok(ServiceRead::Read)
            }
            Err(error) => return Err(error),
        };
        match self.handle_feedback_and_retransmit_from(from, feedback) {
            Ok(_) => Ok(ServiceRead::Read),
            Err(error) if service_read_error_is_local(&error) => Ok(ServiceRead::Read),
            Err(error) => Err(error),
        }
    }

    /// Retries queued datagrams in FIFO order. A `WouldBlock` condition keeps
    /// the exact encoded bytes at the head of the bounded queue.
    pub fn flush_pending(&mut self) -> io::Result<usize> {
        let sent = flush_queue(&mut self.rtp_socket, &mut self.pending, &mut self.spare)?;
        Ok(sent
            + flush_queue(
                &mut self.rtcp_socket,
                &mut self.rtcp_pending,
                &mut self.spare,
            )?)
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
        queue_datagram(&mut self.pending, &mut self.spare, peer, packet, &[]);
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

    pub fn configure_multicast(
        &self,
        interface: &NetworkInterface,
        ttl_or_hops: Option<u8>,
        loopback: bool,
    ) -> io::Result<()> {
        self.rtp_socket.set_multicast_interface(interface)?;
        self.rtcp_socket.set_multicast_interface(interface)?;
        if self.local_addr()?.is_ipv4() {
            self.set_multicast_loop_v4(loopback)?;
            if let Some(ttl) = ttl_or_hops {
                self.set_multicast_ttl_v4(u32::from(ttl))?;
            }
        } else {
            self.rtp_socket.set_multicast_loop_v6(loopback)?;
            self.rtcp_socket.set_multicast_loop_v6(loopback)?;
            if let Some(hops) = ttl_or_hops {
                self.rtp_socket.set_multicast_hops_v6(u32::from(hops))?;
                self.rtcp_socket.set_multicast_hops_v6(u32::from(hops))?;
            }
        }
        Ok(())
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
        self.poll_repairs_and_send(now)?;
        self.ensure_rtcp_pending_capacity()?;
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.send_rtcp(&packet).map(Some)
    }

    /// Reads one feedback datagram and sends what it asks for. When the
    /// socket is drained, sends the repairs due on the sender's own
    /// schedule (see [`Self::poll_repairs_and_send`]) and returns `None`.
    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let Some((from, feedback)) = self.rtcp_socket.recv_datagram(buf)? else {
            self.inline.wake_at = None;
            self.poll_due_repairs()?;
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
            self.inline.wake_at = None;
            self.poll_due_repairs()?;
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
        let outcome = self
            .core
            .handle_feedback_outcome_at(feedback, ntp_now(), Instant::now())
            .map_err(core_to_io_error)?;
        self.peer = Some(rtp_peer);
        self.send_feedback_outcome(&outcome)?;
        Ok(Some(outcome.retries))
    }

    /// Sends the repairs the sender owes on its own schedule that are due at
    /// `now`: second copies of late repairs (and tail probes). The receive
    /// calls and [`Self::poll_rtcp_and_send`] call this; a caller that
    /// sleeps can wake at [`Self::next_timeout`]. A full send queue drops
    /// the rest (they are extra copies). Returns the repairs queued.
    pub fn poll_repairs_and_send(&mut self, now: Instant) -> io::Result<usize> {
        if self.peer.is_none() || self.core.next_repair_at().map_or(true, |at| at > now) {
            return Ok(0);
        }
        let mut queued = 0;
        for repair in self.core.poll_repairs_at(now) {
            match self.enqueue_packet(&repair.bytes) {
                Ok(()) => queued += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.flush_pending()?;
        Ok(queued)
    }

    fn poll_due_repairs(&mut self) -> io::Result<()> {
        if self.core.next_repair_at().is_some() {
            self.poll_repairs_and_send(Instant::now())?;
        }
        Ok(())
    }

    /// When the sender next has something to send on its own: an SR or
    /// echo request ([`Self::poll_rtcp_and_send`]) or a scheduled repair;
    /// `now` when the send path left feedback unread.
    pub fn next_timeout(&self) -> Option<Instant> {
        [
            self.core.next_rtcp_at(),
            self.core.next_repair_at(),
            self.inline.wake_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Echo responses first (best effort: a full queue drops them, as a
    /// lost datagram would), then the retransmissions.
    fn send_feedback_outcome(&mut self, outcome: &FeedbackOutcome) -> io::Result<()> {
        for response in &outcome.responses {
            match self.send_rtcp(response) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        for retry in &outcome.retries {
            self.send_outbound(retry)?;
        }
        Ok(())
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
        let outcome = self
            .core
            .handle_feedback_outcome_at(feedback, now_ntp, Instant::now())
            .map_err(core_to_io_error)?;
        self.peer = Some(rtp_peer);
        self.send_feedback_outcome(&outcome)?;
        Ok(outcome.retries)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.rtp_socket.local_addr()
    }

    pub fn rtcp_local_addr(&self) -> io::Result<SocketAddr> {
        self.rtcp_socket.local_addr()
    }

    pub fn socket_buffer_sizes(&self) -> io::Result<SimpleSocketBufferSizes> {
        Ok(SimpleSocketBufferSizes {
            rtp: self.rtp_socket.socket_buffer_sizes()?,
            rtcp: self.rtcp_socket.socket_buffer_sizes()?,
        })
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SimpleSocketBufferSizes> {
        self.rtp_socket.set_socket_buffer_sizes(receive, send)?;
        self.rtcp_socket.set_socket_buffer_sizes(receive, send)?;
        self.socket_buffer_sizes()
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

    pub fn join_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.rtp_socket.join_multicast(group, interface, source)?;
        let result = self.rtcp_socket.join_multicast(group, interface, source);
        if result.is_err() {
            let _ = self.rtp_socket.leave_multicast(group, interface, source);
        }
        result
    }

    pub fn leave_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.rtp_socket.leave_multicast(group, interface, source)?;
        self.rtcp_socket.leave_multicast(group, interface, source)
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

/// Mio readiness for a Simple Profile receiver covers both its sockets under
/// the one token: RTP payloads and the RTCP the sender sends (echo requests
/// and answers, sender reports). [`SimpleMioReceiver::try_recv_event`] reads
/// both; RTCP sending stays deadline-driven
/// ([`SimpleMioReceiver::next_timeout`]).
impl Source for SimpleMioReceiver {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.rtp_socket.register(registry, token, interests)?;
        self.rtcp_socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.rtp_socket.reregister(registry, token, interests)?;
        self.rtcp_socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.rtp_socket.deregister(registry)?;
        self.rtcp_socket.deregister(registry)
    }
}

/// One datagram read by [`SimpleMioReceiver::try_recv_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleReceiverEvent {
    Payload {
        from: SocketAddr,
        payload: ReceivedPayload,
    },
    /// An RTCP compound from the sender, handled; `responses` answers (echo
    /// responses) were sent back.
    Rtcp { from: SocketAddr, responses: usize },
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
        ensure_same_address_family(local, peer)?;
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
        Ok(self
            .accept_rtp_datagram(from, packet)?
            .map(|payload| (from, payload)))
    }

    /// `None` for a datagram from a peer other than the configured one.
    fn accept_rtp_datagram(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
    ) -> io::Result<Option<ReceivedPayload>> {
        if self.configured_peer.is_some_and(|peer| peer != from) {
            return Ok(None);
        }
        let payload = self.core.accept_packet(packet).map_err(core_to_io_error)?;
        self.last_rtp_peer = Some(from);
        if self.last_rtcp_peer.is_none() {
            // A bound receiver that only reads payloads still has a place
            // to send NACKs and reports: the sender's RTCP port is the one
            // after its RTP port (RFC 3550, as librist sends from).
            self.last_rtcp_peer = simple_rtcp_addr(from).ok();
        }
        Ok(Some(payload))
    }

    /// Reads one datagram from either socket: a payload first, else an RTCP
    /// compound (answered as [`Self::try_recv_rtcp_and_respond`] does).
    /// `None` only when both sockets are drained, so a caller that
    /// registers the receiver with mio and loops on this until `None`
    /// serves both.
    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<SimpleReceiverEvent>> {
        while let Some((from, packet)) = self.rtp_socket.recv_datagram(buf)? {
            if let Some(payload) = self.accept_rtp_datagram(from, packet)? {
                return Ok(Some(SimpleReceiverEvent::Payload { from, payload }));
            }
        }
        loop {
            let Some((from, packet)) = self.rtcp_socket.recv_datagram(buf)? else {
                return Ok(None);
            };
            if let Some(responses) = self.handle_rtcp_datagram(from, packet)? {
                return Ok(Some(SimpleReceiverEvent::Rtcp { from, responses }));
            }
        }
    }

    pub fn set_recovery_config(
        &mut self,
        recovery: RecoveryConfig,
        congestion_control: CongestionControlMode,
    ) {
        self.core.set_recovery_config(recovery, congestion_control);
    }

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.core.set_recovery_tuning(tuning);
    }

    /// When [`Self::poll_rtcp_and_send`] next has something to send (a due
    /// NACK, echo request or report), so a caller can sleep until then
    /// instead of polling on a fixed period. `None`: nothing scheduled (or
    /// no RTCP peer known yet); wait for data. It can be early, never late.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.last_rtcp_peer?;
        self.core.next_poll_at()
    }

    pub fn feedback_packet(&mut self) -> Vec<u8> {
        self.core.build_feedback_and_record()
    }

    pub fn poll_rtcp_packet(&mut self, now: Instant, now_ntp: u64) -> Option<Vec<u8>> {
        self.core.poll_rtcp(now, now_ntp)
    }

    /// Sends every due RTCP packet (all due NACK packets, oldest holes
    /// first, or a periodic receiver report) and returns the bytes sent.
    ///
    /// Holes count as NACKed only when their packet was sent. When a send
    /// fails, the rest of the batch is not sent and its holes stay due for
    /// the next poll; the bytes already sent are returned, or the error when
    /// nothing went out.
    pub fn poll_rtcp_and_send(&mut self, now: Instant, now_ntp: u64) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_rtcp_peer else {
            return Ok(None);
        };
        let socket = &mut self.rtcp_socket;
        let mut sent = 0;
        let mut error = None;
        let packets = self.core.poll_rtcp_with(
            now,
            now_ntp,
            rist_core::simple::MAX_NACK_PACKETS_PER_POLL,
            |packet| match socket.send_packet_to(peer, packet) {
                Ok(bytes) => {
                    sent += bytes;
                    true
                }
                Err(err) => {
                    error = Some(err);
                    false
                }
            },
        );
        match error {
            Some(error) if packets == 0 => Err(error),
            _ if packets == 0 => Ok(None),
            _ => Ok(Some(sent)),
        }
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
        self.handle_rtcp_datagram(from, packet)
    }

    /// `None` for a datagram from a peer other than the configured one.
    fn handle_rtcp_datagram(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
    ) -> io::Result<Option<usize>> {
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

    pub fn socket_buffer_sizes(&self) -> io::Result<SimpleSocketBufferSizes> {
        Ok(SimpleSocketBufferSizes {
            rtp: self.rtp_socket.socket_buffer_sizes()?,
            rtcp: self.rtcp_socket.socket_buffer_sizes()?,
        })
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SimpleSocketBufferSizes> {
        self.rtp_socket.set_socket_buffer_sizes(receive, send)?;
        self.rtcp_socket.set_socket_buffer_sizes(receive, send)?;
        self.socket_buffer_sizes()
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

    pub fn join_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.rtp_socket.join_multicast(group, interface, source)?;
        let result = self.rtcp_socket.join_multicast(group, interface, source);
        if result.is_err() {
            let _ = self.rtp_socket.leave_multicast(group, interface, source);
        }
        result
    }

    pub fn leave_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.rtp_socket.leave_multicast(group, interface, source)?;
        self.rtcp_socket.leave_multicast(group, interface, source)
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
    /// Buffers of sent queued datagrams, reused by the next ones queued.
    spare: Vec<Vec<u8>>,
    /// When the SR/echo or keepalive timer is next due: `send_payload`
    /// serves them itself once this has passed (`None`: not armed yet).
    next_timer_at: Option<Instant>,
    /// The keepalive `send_payload` sends on its own once due; `None` (the
    /// default) leaves keepalives to the caller's
    /// `poll_session_and_send_keepalive`.
    auto_keepalive: Option<KeepaliveTemplate>,
    /// Feedback served from inside the send path (see
    /// [`INLINE_SERVICE_EVERY`]).
    inline: InlineService,
    /// Events other than feedback read by the send path, returned first
    /// by [`MainMioSender::try_recv_event`].
    inline_events: VecDeque<MainSenderEvent>,
}

/// Readiness of a Main sender is its socket's: feedback to read (with
/// `Interest::READABLE`). Sleep until [`MainMioSender::next_timeout`] (or
/// the `service` result) and call [`MainMioSender::service`] on wakeup.
impl Source for MainMioSender {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.socket.deregister(registry)
    }
}

/// The most feedback datagrams one [`MainMioSender::service`] call reads.
const SERVICE_READ_LIMIT: usize = 512;

/// Every this many data packets the send path itself reads and serves
/// waiting feedback (NACKs are repaired, echo requests answered) and sends
/// due repairs: a repair never waits behind a large frame for the caller's
/// next `service`. One non-blocking read when nothing waits.
pub const INLINE_SERVICE_EVERY: u32 = 32;

/// The most feedback datagrams one inline service reads.
const INLINE_READ_LIMIT: usize = 64;

/// The most events (other than feedback) the send path keeps for
/// `try_recv_event`; the oldest is dropped past it.
const INLINE_EVENT_LIMIT: usize = 64;

/// State of the feedback service inside the send path.
#[derive(Debug, Default)]
struct InlineService {
    /// Data packets sent since the last inline service.
    sends: u32,
    /// The receive buffer (allocated at the first inline read).
    buf: Vec<u8>,
    /// When the caller should come back: datagrams were left unread, or
    /// events wait for `try_recv_event` (the socket's readiness may have
    /// been consumed by the inline read).
    wake_at: Option<Instant>,
}

impl InlineService {
    /// Counts one data packet; true when the inline service is due.
    fn due(&mut self) -> bool {
        self.sends += 1;
        if self.sends < INLINE_SERVICE_EVERY {
            return false;
        }
        self.sends = 0;
        true
    }

    fn take_buf(&mut self) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.buf);
        if buf.len() < SAFE_RECEIVE_CAPACITY {
            buf.resize(SAFE_RECEIVE_CAPACITY, 0);
        }
        buf
    }

    fn wake(&mut self, at: Instant) {
        self.wake_at = Some(self.wake_at.map_or(at, |wake| wake.min(at)));
    }
}

/// How soon `service` asks to be called again while datagrams wait in the
/// send queue.
const PENDING_RETRY: std::time::Duration = std::time::Duration::from_millis(1);

/// An owned [`GreKeepalive`]: what a sender sends on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeepaliveTemplate {
    mac: [u8; 6],
    capabilities1: u8,
    capabilities2: u8,
    json: Vec<u8>,
}

impl KeepaliveTemplate {
    fn from_gre(keepalive: GreKeepalive<'_>) -> Self {
        Self {
            mac: keepalive.mac,
            capabilities1: keepalive.capabilities1,
            capabilities2: keepalive.capabilities2,
            json: keepalive.json.to_vec(),
        }
    }

    fn as_gre(&self) -> GreKeepalive<'_> {
        GreKeepalive {
            mac: self.mac,
            capabilities1: self.capabilities1,
            capabilities2: self.capabilities2,
            json: &self.json,
        }
    }

    /// Sets the MAC of `template`, starting from librist's default.
    fn set_mac(template: &mut Option<Self>, mac: [u8; 6]) {
        match template {
            Some(template) => template.mac = mac,
            None => *template = Some(Self::from_gre(GreKeepalive::librist_default(mac))),
        }
    }

    /// The keepalive `service` sends: the template, or librist's default.
    fn or_default(template: Option<&Self>) -> GreKeepalive<'_> {
        template.map_or(GreKeepalive::librist_default([0; 6]), Self::as_gre)
    }
}

/// What one read in a `service` loop found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceRead {
    /// The socket is empty.
    Drained,
    /// A datagram was read (handled, ignored or malformed): read on.
    Read,
}

/// Whether an error from handling one datagram that was read leaves the
/// `service` loop reading: malformed or unexpected input, or a full queue
/// (the loop checks the queue itself).
fn service_read_error_is_local(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::WouldBlock
    )
}

/// The deadline `service` returns: `now` when reads stopped at the limit,
/// soon when datagrams wait in the send queue, else `next`.
fn service_deadline(
    now: Instant,
    next: Option<Instant>,
    more_to_read: bool,
    pending: bool,
) -> Option<Instant> {
    if more_to_read {
        return Some(now);
    }
    if !pending {
        return next;
    }
    let retry = now + PENDING_RETRY;
    Some(next.map_or(retry, |next| next.min(retry)))
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
        ensure_same_address_family(local, peer)?;
        // Connected: the kernel keeps the route and the address, so each
        // send skips the route lookup, and only the peer's datagrams are
        // read (others were ignored anyway).
        let socket = RtpUdpSocket::connect(local, peer, flow_id)?;
        Ok(Self::with_socket(
            socket,
            flow_id,
            history_packets,
            Some(peer),
        ))
    }

    pub fn listen(local: SocketAddr, flow_id: u32, history_packets: usize) -> io::Result<Self> {
        let socket = RtpUdpSocket::bind(local, flow_id)?;
        Ok(Self::with_socket(socket, flow_id, history_packets, None))
    }

    fn with_socket(
        socket: RtpUdpSocket,
        flow_id: u32,
        history_packets: usize,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            socket,
            core: MainSenderCore::new(flow_id, history_packets),
            timers: MainSessionTimers::new(),
            srp: None,
            srp_authenticator: None,
            srp_candidates: HashMap::new(),
            peer,
            listening: peer.is_none(),
            last_reauthentication: None,
            pending: VecDeque::with_capacity(PENDING_SEND_CAPACITY),
            spare: Vec::new(),
            next_timer_at: None,
            auto_keepalive: None,
            inline: InlineService::default(),
            inline_events: VecDeque::new(),
        }
    }

    /// Has [`Self::send_payload`] send librist's default keepalive with
    /// this MAC-like id once due (keeping the capabilities and JSON of a
    /// keepalive set with [`Self::set_auto_keepalive`]), and
    /// [`Self::service`] send it too. Without it `send_payload` leaves
    /// keepalives to [`Self::poll_session_and_send_keepalive`], and
    /// `service` sends librist's default with a zero MAC.
    pub fn set_keepalive_mac(&mut self, mac: [u8; 6]) {
        KeepaliveTemplate::set_mac(&mut self.auto_keepalive, mac);
    }

    /// Has [`Self::send_payload`] and [`Self::service`] send `keepalive`
    /// (copied) once due: see [`Self::set_keepalive_mac`].
    pub fn set_auto_keepalive(&mut self, keepalive: GreKeepalive<'_>) {
        self.auto_keepalive = Some(KeepaliveTemplate::from_gre(keepalive));
    }

    /// Leaves keepalives to the caller again: `send_payload` sends none.
    pub fn disable_auto_keepalive(&mut self) {
        self.auto_keepalive = None;
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

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.core.set_recovery_tuning(tuning);
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
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.flush_pending()?;
        self.send_or_queue(peer, &packet.bytes, &[])?;
        Ok(packet.bytes.len())
    }

    /// Sends one payload and returns the datagram sent. Also serves the
    /// SR/echo and keepalive timers when they are due, so a caller that
    /// only sends still sends reports and echo requests (the receiver
    /// needs them for its RTT). Use [`Self::send_payload_meta`] when the
    /// bytes are not needed: it allocates nothing.
    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<MainOutboundPacket> {
        let mut bytes = Vec::new();
        let meta = self.send_payload_parts(payload, ntp_timestamp, now, |head, body| {
            bytes.reserve_exact(head.len() + body.len());
            bytes.extend_from_slice(head);
            bytes.extend_from_slice(body);
        })?;
        Ok(MainOutboundPacket {
            rtp_sequence: meta.rtp_sequence,
            gre_sequence: meta.gre_sequence,
            retry: false,
            bytes,
        })
    }

    /// [`Self::send_payload`] without the bytes: the RTP packet is encoded
    /// into its history slot and sent from there with its GRE header in one
    /// `sendmsg`. One copy of the payload, no allocation once warm.
    pub fn send_payload_meta(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<MainPacketMeta> {
        self.send_payload_parts(payload, ntp_timestamp, now, |_, _| {})
    }

    fn send_payload_parts(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
        observe: impl FnOnce(&[u8], &[u8]),
    ) -> io::Result<MainPacketMeta> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.ensure_srp_authenticated()?;
        // A full queue refuses before the sequence and history commit.
        self.ensure_pending_capacity()?;
        if !self.pending.is_empty() {
            self.flush_pending()?;
        }
        let Self {
            core,
            socket,
            pending,
            spare,
            ..
        } = self;
        let meta = core.send_payload_with(payload, ntp_timestamp, now, |meta, head, body| {
            observe(head, body);
            send_or_queue(socket, pending, spare, peer, head, body).map(|()| meta)
        })?;
        self.drive_timers(now, ntp_timestamp);
        if self.inline.due() {
            self.serve_inline(now);
        }
        Ok(meta)
    }

    /// The send path's own feedback service (every
    /// [`INLINE_SERVICE_EVERY`] data packets): reads up to 64 waiting
    /// datagrams and handles them as [`Self::service`] does (feedback
    /// repaired, echo requests answered; other events kept for
    /// [`Self::try_recv_event`]), then sends due repairs. Errors are left
    /// for `service`: the data packet already went out.
    fn serve_inline(&mut self, now: Instant) {
        if !self.srp_authenticated() {
            return;
        }
        let mut buf = self.inline.take_buf();
        let mut drained = false;
        for _ in 0..INLINE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY {
                break;
            }
            let (from, datagram) = match self.socket.recv_datagram(&mut buf) {
                Ok(Some(received)) => received,
                Ok(None) => {
                    drained = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                Err(_) => break,
            };
            match self.handle_datagram(from, datagram) {
                Ok(MainSenderEvent::Feedback { .. }) => {}
                Ok(event) => {
                    if self.inline_events.len() >= INLINE_EVENT_LIMIT {
                        self.inline_events.pop_front();
                    }
                    self.inline_events.push_back(event);
                    self.inline.wake(now);
                }
                Err(_) => {}
            }
        }
        self.inline.buf = buf;
        if !drained {
            self.inline.wake(now);
        }
        let _ = self.poll_repairs_and_send(now);
    }

    /// Sends the SR/echo request when due, and the keepalive when the
    /// caller opted in ([`Self::set_keepalive_mac`]); two `Instant`
    /// comparisons when nothing is due. Errors are left for
    /// [`Self::service`] or the next poll: the data packet already went out.
    fn drive_timers(&mut self, now: Instant, ntp_timestamp: u64) {
        if self.next_timer_at.is_some_and(|at| now < at) {
            return;
        }
        if let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) {
            let _ = self.send_control(&packet.bytes);
        }
        if let Some(keepalive) = &self.auto_keepalive {
            if self.timers.poll(now).keepalive_due {
                let packet = self.core.build_keepalive(keepalive.as_gre());
                let _ = self.send_control(&packet.bytes);
            }
        }
        self.next_timer_at = Some(
            self.send_timer_at()
                .unwrap_or(now + std::time::Duration::from_millis(100)),
        );
    }

    /// When `send_payload` next has a timer to serve: the SR/echo request,
    /// and the keepalive if it sends them.
    fn send_timer_at(&self) -> Option<Instant> {
        let keepalive = self
            .auto_keepalive
            .as_ref()
            .and_then(|_| self.timers.next_keepalive_at());
        [self.core.next_rtcp_at(), keepalive]
            .into_iter()
            .flatten()
            .min()
    }

    fn send_control(&mut self, bytes: &[u8]) -> io::Result<()> {
        let peer = self.peer.ok_or_else(no_remote_peer_error)?;
        self.send_or_queue(peer, bytes, &[])
    }

    /// Everything a sender owes besides its data, for a caller that sleeps
    /// between events: flushes the send queue, reads and serves feedback
    /// until the socket is drained (at most 512 datagrams; NACKs are
    /// repaired, echo requests answered), sends the SR/echo request and the
    /// keepalive when due (and starts SRP re-authentication after a
    /// timeout), and sends due repairs. Returns when to call it again
    /// (`None`: only when the socket is readable; `now` when it stopped at
    /// the read limit). Malformed or ignored datagrams are skipped. Without
    /// a peer (listening) only the reads happen. The keepalive is the one
    /// set with [`Self::set_auto_keepalive`], else librist's default.
    pub fn service(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
        buf: &mut [u8],
    ) -> io::Result<Option<Instant>> {
        // Events the send path kept are dropped here, as `service` drops
        // the events it reads itself.
        self.inline_events.clear();
        self.inline.wake_at = None;
        self.inline.sends = 0;
        self.flush_pending()?;
        // Reads until the socket is empty or the queue cannot take repairs;
        // stopped at the limit, datagrams may still wait, and an
        // edge-triggered source gets no new readiness for them.
        let mut more_to_read = true;
        for _ in 0..SERVICE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY
                || self.service_read(buf)? == ServiceRead::Drained
            {
                more_to_read = false;
                break;
            }
        }
        if self.peer.is_some() && self.srp_authenticated() {
            match self.poll_rtcp_and_send(now, ntp_timestamp) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if self.peer.is_some() {
            let template = self.auto_keepalive.take();
            let keepalive = KeepaliveTemplate::or_default(template.as_ref());
            let result = self.poll_session_and_send_keepalive(now, keepalive);
            self.auto_keepalive = template;
            match result {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            self.poll_repairs_and_send(now)?;
        }
        self.next_timer_at = self.send_timer_at();
        Ok(service_deadline(
            now,
            self.next_timeout(),
            more_to_read,
            !self.pending.is_empty(),
        ))
    }

    /// One read of the `service` loop.
    fn service_read(&mut self, buf: &mut [u8]) -> io::Result<ServiceRead> {
        let (from, datagram) = match self.socket.recv_datagram(buf) {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(ServiceRead::Drained),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return Ok(ServiceRead::Read)
            }
            Err(error) => return Err(error),
        };
        match self.handle_datagram(from, datagram) {
            Ok(_) => Ok(ServiceRead::Read),
            Err(error) if service_read_error_is_local(&error) => Ok(ServiceRead::Read),
            Err(error) => Err(error),
        }
    }

    fn send_or_queue(&mut self, peer: SocketAddr, head: &[u8], body: &[u8]) -> io::Result<()> {
        send_or_queue(
            &mut self.socket,
            &mut self.pending,
            &mut self.spare,
            peer,
            head,
            body,
        )
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<MainControlPacket>> {
        self.ensure_peer_available()?;
        self.ensure_srp_authenticated()?;
        self.poll_repairs_and_send(now)?;
        self.ensure_pending_capacity()?;
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.enqueue_packet(&packet.bytes)?;
        self.flush_pending()?;
        Ok(Some(packet))
    }

    /// Sends the repairs the sender owes on its own schedule that are due at
    /// `now`: second copies of late repairs (and tail probes). The receive
    /// calls and [`Self::poll_rtcp_and_send`] call this; a caller that
    /// sleeps can wake at [`Self::next_timeout`]. A full send queue drops
    /// the rest (they are extra copies). Returns the repairs queued.
    pub fn poll_repairs_and_send(&mut self, now: Instant) -> io::Result<usize> {
        if self.peer.is_none()
            || !self.srp_authenticated()
            || self.core.next_repair_at().map_or(true, |at| at > now)
        {
            return Ok(0);
        }
        let mut queued = 0;
        for repair in self.core.poll_repairs(now) {
            match self.enqueue_packet(&repair.bytes) {
                Ok(()) => queued += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.flush_pending()?;
        Ok(queued)
    }

    /// When the sender next has something to send on its own: an SR or
    /// echo request ([`Self::poll_rtcp_and_send`]), a keepalive
    /// ([`Self::poll_session_and_send_keepalive`]) or a scheduled repair.
    /// Without a peer, or while SRP is not authenticated (say during a
    /// re-authentication), only keepalives go out, so only their timer
    /// counts: the others stay where they were until data may flow again.
    ///
    /// It is `now` (or earlier) when the send path read feedback on its own
    /// and left datagrams or events waiting: the socket may not signal
    /// readiness for them again.
    pub fn next_timeout(&self) -> Option<Instant> {
        let sending = self.peer.is_some() && self.srp_authenticated();
        let (rtcp, repair) = if sending {
            (self.core.next_rtcp_at(), self.core.next_repair_at())
        } else {
            (None, None)
        };
        [
            rtcp,
            repair,
            self.timers.next_keepalive_at(),
            self.inline.wake_at,
        ]
        .into_iter()
        .flatten()
        .min()
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

    /// Reads one datagram and handles it (feedback is answered and its
    /// retransmissions sent). When the socket is drained, sends the repairs
    /// due on the sender's own schedule (see [`Self::poll_repairs_and_send`])
    /// and returns `None`.
    ///
    /// Events the send path read on its own (see [`INLINE_SERVICE_EVERY`])
    /// come first; feedback it served is not reported again.
    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<MainSenderEvent>> {
        if let Some(event) = self.inline_events.pop_front() {
            return Ok(Some(event));
        }
        let Some((from, datagram)) = self.socket.recv_datagram(buf)? else {
            self.inline.wake_at = None;
            if self.core.next_repair_at().is_some() {
                self.poll_repairs_and_send(Instant::now())?;
            }
            return Ok(None);
        };
        self.handle_datagram(from, datagram).map(Some)
    }

    /// Handles one datagram read from the socket.
    fn handle_datagram(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
    ) -> io::Result<MainSenderEvent> {
        let packet = self
            .core
            .decode_datagram(datagram)
            .map_err(core_to_io_error)?;
        if self.peer.is_some_and(|peer| peer != from) {
            return Ok(MainSenderEvent::Unhandled { from, packet });
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
                return Ok(MainSenderEvent::Unhandled { from, packet });
            }
            MainPacket::Reduced(packet) if looks_like_rtcp(&packet.payload) => {
                let now = Instant::now();
                let outcome = self
                    .core
                    .handle_reduced_feedback_outcome(
                        packet.reduced,
                        &packet.payload,
                        ntp_now(),
                        now,
                    )
                    .map_err(core_to_io_error)?;
                self.select_unsecured_listener_peer(from);
                for response in &outcome.responses {
                    // Best effort: a full queue drops an echo response as a
                    // lost datagram would.
                    match self.enqueue_packet(&response.bytes) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error),
                    }
                }
                for retry in &outcome.retries {
                    self.send_outbound(retry)?;
                }
                if outcome.retries.is_empty() && !outcome.responses.is_empty() {
                    self.flush_pending()?;
                }
                self.timers.observe_peer_activity(now);
                MainSenderEvent::Feedback {
                    from,
                    retries: outcome.retries,
                }
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
        Ok(event)
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
        flush_queue(&mut self.socket, &mut self.pending, &mut self.spare)
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
        queue_datagram(&mut self.pending, &mut self.spare, peer, packet, &[]);
        Ok(())
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn socket_buffer_sizes(&self) -> io::Result<SocketBufferSizes> {
        self.socket.socket_buffer_sizes()
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SocketBufferSizes> {
        self.socket.set_socket_buffer_sizes(receive, send)
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

    pub fn configure_multicast(
        &self,
        interface: &NetworkInterface,
        ttl_or_hops: Option<u8>,
        loopback: bool,
    ) -> io::Result<()> {
        self.socket.set_multicast_interface(interface)?;
        if self.local_addr()?.is_ipv4() {
            self.socket.set_multicast_loop_v4(loopback)?;
            if let Some(ttl) = ttl_or_hops {
                self.socket.set_multicast_ttl_v4(u32::from(ttl))?;
            }
        } else {
            self.socket.set_multicast_loop_v6(loopback)?;
            if let Some(hops) = ttl_or_hops {
                self.socket.set_multicast_hops_v6(u32::from(hops))?;
            }
        }
        Ok(())
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
    /// When the SR/echo or a keepalive timer is next due (see
    /// [`MainMioSender`]).
    next_timer_at: Option<Instant>,
    /// The keepalive `send_payload` sends on its own (see
    /// [`MainMioSender`]); `None` leaves them to the caller.
    auto_keepalive: Option<KeepaliveTemplate>,
    /// Feedback served from inside the send path, and the other events it
    /// read (see [`MainMioSender`]).
    inline: InlineService,
    inline_events: VecDeque<MainSenderEvent>,
}

/// Readiness of a multi-peer sender is its socket's (feedback from every
/// peer). Sleep until the [`MainMioMultiSender::service`] deadline.
impl Source for MainMioMultiSender {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.socket.deregister(registry)
    }
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
            next_timer_at: None,
            auto_keepalive: None,
            inline: InlineService::default(),
            inline_events: VecDeque::new(),
        })
    }

    /// Has `send_payload` send every peer librist's default keepalive with
    /// this MAC-like id once due; see [`MainMioSender::set_keepalive_mac`].
    pub fn set_keepalive_mac(&mut self, mac: [u8; 6]) {
        KeepaliveTemplate::set_mac(&mut self.auto_keepalive, mac);
    }

    /// Has `send_payload` and `service` send `keepalive` (copied) once due.
    pub fn set_auto_keepalive(&mut self, keepalive: GreKeepalive<'_>) {
        self.auto_keepalive = Some(KeepaliveTemplate::from_gre(keepalive));
    }

    /// Leaves keepalives to the caller again: `send_payload` sends none.
    pub fn disable_auto_keepalive(&mut self) {
        self.auto_keepalive = None;
    }

    /// Everything the sender owes besides data (see
    /// [`MainMioSender::service`]): flushes the queue, serves feedback from
    /// every peer until the socket is drained (at most 512 datagrams;
    /// datagrams from unknown sources are read and ignored), sends the
    /// SR/echo request to the authenticated peers, keepalives and due
    /// repairs, and returns when to call it again (`now` when it stopped at
    /// the read limit).
    pub fn service(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
        buf: &mut [u8],
    ) -> io::Result<Option<Instant>> {
        self.inline_events.clear();
        self.inline.wake_at = None;
        self.inline.sends = 0;
        self.flush_pending()?;
        let mut more_to_read = true;
        for _ in 0..SERVICE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY
                || self.service_read(buf)? == ServiceRead::Drained
            {
                more_to_read = false;
                break;
            }
        }
        if !self.peers.is_empty() {
            self.serve_timers(now, ntp_timestamp, true)?;
            self.poll_repairs_and_send(now)?;
        }
        Ok(service_deadline(
            now,
            self.next_timeout(),
            more_to_read,
            !self.pending.is_empty(),
        ))
    }

    /// One read of the `service` loop.
    fn service_read(&mut self, buf: &mut [u8]) -> io::Result<ServiceRead> {
        let (from, datagram) = match self.socket.recv_datagram(buf) {
            Ok(Some(received)) => received,
            Ok(None) => return Ok(ServiceRead::Drained),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return Ok(ServiceRead::Read)
            }
            Err(error) => return Err(error),
        };
        match self.handle_datagram(from, datagram) {
            Ok(_) => Ok(ServiceRead::Read),
            Err(error) if service_read_error_is_local(&error) => Ok(ServiceRead::Read),
            Err(error) => Err(error),
        }
    }

    /// SR/echo (to the authenticated peers) and, with `keepalives`, the
    /// keepalives (the auto keepalive, else librist's default); a full
    /// queue (`WouldBlock`) leaves them for the next call.
    fn serve_timers(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
        keepalives: bool,
    ) -> io::Result<()> {
        match self.poll_rtcp_and_send(now, ntp_timestamp) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(error),
        }
        if keepalives {
            let template = self.auto_keepalive.take();
            let keepalive = KeepaliveTemplate::or_default(template.as_ref());
            let result = self.poll_session_and_send_keepalive(now, keepalive);
            self.auto_keepalive = template;
            match result {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        let keepalive_at = self
            .auto_keepalive
            .as_ref()
            .and_then(|_| self.next_keepalive_at());
        self.next_timer_at = [self.next_rtcp_at(), keepalive_at]
            .into_iter()
            .flatten()
            .min();
        Ok(())
    }

    /// The SR/echo timer, while any peer is authenticated to take them.
    fn next_rtcp_at(&self) -> Option<Instant> {
        if self.peer_runtime.iter().any(peer_authenticated) {
            self.core.next_rtcp_at()
        } else {
            None
        }
    }

    fn next_keepalive_at(&self) -> Option<Instant> {
        self.peer_runtime
            .iter()
            .filter_map(|runtime| runtime.timers.next_keepalive_at())
            .min()
    }

    pub fn add_peer(&mut self, peer: SocketAddr, weight: u32) -> io::Result<usize> {
        ensure_same_address_family(self.socket.local_addr()?, peer)?;
        let index = self.peers.len();
        self.peers.push(MainMioPeer { addr: peer, weight });
        self.peer_runtime.push(MainMultiSenderPeerRuntime {
            sender: self.core.new_peer_state(),
            timers: MainSessionTimers::with_config(self.session_config),
            srp: self.srp.clone(),
            last_reauthentication: None,
        });
        self.selector.add_peer(weight);
        Ok(index)
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
        // A sender that is only handed data still sends its SR/echo request
        // and keepalives once due; errors wait for `service`.
        let keepalives = self.auto_keepalive.is_some();
        if self.next_timer_at.map_or(true, |at| now >= at)
            && (self.serve_timers(now, ntp_timestamp, keepalives).is_err()
                || self.next_timer_at.is_none())
        {
            self.next_timer_at = Some(now + std::time::Duration::from_millis(100));
        }
        if self.inline.due() {
            self.serve_inline(now);
        }
        Ok(MainMioMultiSend {
            peers,
            peer_packets,
        })
    }

    /// The send path's own feedback service; see [`MainMioSender`].
    fn serve_inline(&mut self, now: Instant) {
        let mut buf = self.inline.take_buf();
        let mut drained = false;
        for _ in 0..INLINE_READ_LIMIT {
            if self.pending.len() >= PENDING_SEND_CAPACITY {
                break;
            }
            let (from, datagram) = match self.socket.recv_datagram(&mut buf) {
                Ok(Some(received)) => received,
                Ok(None) => {
                    drained = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                Err(_) => break,
            };
            match self.handle_datagram(from, datagram) {
                Ok(Some(MainSenderEvent::Feedback { .. })) | Ok(None) | Err(_) => {}
                Ok(Some(event)) => {
                    if self.inline_events.len() >= INLINE_EVENT_LIMIT {
                        self.inline_events.pop_front();
                    }
                    self.inline_events.push_back(event);
                    self.inline.wake(now);
                }
            }
        }
        self.inline.buf = buf;
        if !drained {
            self.inline.wake(now);
        }
        let _ = self.poll_repairs_and_send(now);
    }

    /// Sends the SR/echo request when due, to the peers the selector picks
    /// that are authenticated (or, when it picks none of them, to every
    /// authenticated peer): a peer that re-authenticates does not hold up
    /// the others' reports and RTT. `PermissionDenied` when no peer is
    /// authenticated.
    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<(MainControlPacket, Vec<usize>)>> {
        if self.peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peers configured",
            ));
        }
        if !self.peer_runtime.iter().any(peer_authenticated) {
            return Err(srp_not_authenticated_error());
        }
        self.poll_repairs_and_send(now)?;
        let Some(payload) = self.core.poll_rtcp_payload(now, ntp_timestamp) else {
            return Ok(None);
        };
        let mut peers = self.select_peers()?;
        peers.retain(|&peer| peer_authenticated(&self.peer_runtime[peer]));
        if peers.is_empty() {
            peers = (0..self.peers.len())
                .filter(|&peer| peer_authenticated(&self.peer_runtime[peer]))
                .collect();
        }
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

    /// Sends every authenticated peer's repairs due at `now` (second copies
    /// of late repairs). A full send queue drops the rest. Returns the
    /// repairs queued.
    pub fn poll_repairs_and_send(&mut self, now: Instant) -> io::Result<usize> {
        if self.next_repair_at().map_or(true, |at| at > now) {
            return Ok(0);
        }
        let mut queued = 0;
        for peer in 0..self.peers.len() {
            if !peer_authenticated(&self.peer_runtime[peer]) {
                continue;
            }
            let repairs = self
                .core
                .poll_repairs_for_peer(&mut self.peer_runtime[peer].sender, now);
            for repair in repairs {
                match self.enqueue_datagram(&repair.bytes, vec![self.peers[peer].addr]) {
                    Ok(()) => queued += 1,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        self.flush_pending()?;
        Ok(queued)
    }

    /// The next repair due to an authenticated peer (the others get none
    /// until they authenticate again).
    fn next_repair_at(&self) -> Option<Instant> {
        self.peer_runtime
            .iter()
            .filter(|runtime| peer_authenticated(runtime))
            .filter_map(|runtime| runtime.sender.next_repair_at())
            .min()
    }

    /// When the sender next has something to send on its own: an SR or
    /// echo request (while any peer is authenticated), a peer keepalive or
    /// a scheduled repair to an authenticated peer.
    pub fn next_timeout(&self) -> Option<Instant> {
        [
            self.next_rtcp_at(),
            self.next_repair_at(),
            self.next_keepalive_at(),
            self.inline.wake_at,
        ]
        .into_iter()
        .flatten()
        .min()
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

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.core.set_recovery_tuning(tuning);
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

    /// Reads one datagram and handles it. When the socket is drained, sends
    /// the repairs due on the sender's own schedule (see
    /// [`Self::poll_repairs_and_send`]) and returns `None`.
    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> io::Result<Option<MainSenderEvent>> {
        if let Some(event) = self.inline_events.pop_front() {
            return Ok(Some(event));
        }
        let Some((from, datagram)) = self.socket.recv_datagram(buf)? else {
            self.inline.wake_at = None;
            if self.next_repair_at().is_some() {
                self.poll_repairs_and_send(Instant::now())?;
            }
            return Ok(None);
        };
        self.handle_datagram(from, datagram)
    }

    /// Handles one datagram read from the socket; `None` when it came from
    /// no configured peer (ignored).
    fn handle_datagram(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
    ) -> io::Result<Option<MainSenderEvent>> {
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
                let outcome = self
                    .core
                    .handle_reduced_feedback_outcome_for_peer(
                        &mut self.peer_runtime[peer].sender,
                        &packet.payload,
                        ntp_now(),
                        Instant::now(),
                    )
                    .map_err(core_to_io_error)?;
                for response in &outcome.responses {
                    match self.enqueue_datagram(&response.bytes, vec![self.peers[peer].addr]) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error),
                    }
                }
                for retry in &outcome.retries {
                    self.enqueue_datagram(&retry.bytes, vec![self.peers[peer].addr])?;
                }
                let retries = outcome.retries;
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

    pub fn socket_buffer_sizes(&self) -> io::Result<SocketBufferSizes> {
        self.socket.socket_buffer_sizes()
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SocketBufferSizes> {
        self.socket.set_socket_buffer_sizes(receive, send)
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

    pub fn configure_multicast(
        &self,
        interface: &NetworkInterface,
        ttl_or_hops: Option<u8>,
        loopback: bool,
    ) -> io::Result<()> {
        self.socket.set_multicast_interface(interface)?;
        if self.local_addr()?.is_ipv4() {
            self.socket.set_multicast_loop_v4(loopback)?;
            if let Some(ttl) = ttl_or_hops {
                self.socket.set_multicast_ttl_v4(u32::from(ttl))?;
            }
        } else {
            self.socket.set_multicast_loop_v6(loopback)?;
            if let Some(hops) = ttl_or_hops {
                self.socket.set_multicast_hops_v6(u32::from(hops))?;
            }
        }
        Ok(())
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

impl Source for MainMioReceiver {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.socket.deregister(registry)
    }
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
        ensure_same_address_family(local, peer)?;
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
        let peers = self.peer_runtime.len();
        let runtime = match self.peer_runtime.entry(from) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                if peers >= self.max_peers {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("RIST Main receiver peer capacity is {}", self.max_peers),
                    ));
                }
                entry.insert(MainReceiverPeerRuntime {
                    core: self.core.fresh_session(),
                    timers: MainSessionTimers::with_config(self.timers.config()),
                    srp: self.srp.clone(),
                    srp_client: self.srp_client.clone(),
                })
            }
        };
        // Data path: a clear reduced data packet is parsed in place, so its
        // payload is copied once, into the `ReceivedPayload`.
        if let Ok(packet) = ReducedPacket::decode(datagram) {
            if !looks_like_rtcp(packet.payload) && receiver_runtime_authenticated(runtime) {
                let now = Instant::now();
                let payload = runtime
                    .core
                    .accept_reduced_at(packet.reduced, packet.payload, now)
                    .map_err(core_to_io_error)?;
                self.last_peer = Some(from);
                runtime.timers.observe_peer_activity(now);
                return Ok(Some(MainReceiverEvent::Payload { from, payload }));
            }
        }
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
                    .accept_reduced_at(packet.reduced, &packet.payload, now)
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

    pub fn set_recovery_tuning(&mut self, tuning: RecoveryTuning) {
        self.core.set_recovery_tuning(tuning);
        for runtime in self.peer_runtime.values_mut() {
            runtime.core.set_recovery_tuning(tuning);
        }
    }

    /// The earliest instant at which [`Self::poll_all_rtcp_and_send`] (or,
    /// for the last peer, [`Self::poll_rtcp_and_send`]) or a peer's
    /// keepalive has something to send. `None`: nothing scheduled; wait for
    /// data. It can be early, never late.
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.peer_runtime.is_empty() {
            return [self.core.next_poll_at(), self.timers.next_keepalive_at()]
                .into_iter()
                .flatten()
                .min();
        }
        self.peer_runtime
            .values()
            .flat_map(|runtime| {
                [
                    runtime.core.next_poll_at(),
                    runtime.timers.next_keepalive_at(),
                ]
            })
            .flatten()
            .min()
    }

    /// [`Self::poll_rtcp_and_send`] for every authenticated peer, not only
    /// the last one heard from, so two contributors on one port both get
    /// NACKs. Returns the number of RTCP packets sent. On a send error the
    /// rest of that peer's batch stays due; the error is returned when
    /// nothing went out.
    pub fn poll_all_rtcp_and_send(&mut self, now: Instant, now_ntp: u64) -> io::Result<usize> {
        let socket = &mut self.socket;
        let mut sent = 0;
        let mut error = None;
        for (&peer, runtime) in self.peer_runtime.iter_mut() {
            if !receiver_runtime_authenticated(runtime) {
                continue;
            }
            sent += runtime
                .core
                .poll_rtcp_all_with(now, now_ntp, |_flow_id, packet| {
                    match socket.send_packet_to(peer, &packet.bytes) {
                        Ok(_) => true,
                        Err(err) => {
                            error = Some(err);
                            false
                        }
                    }
                });
        }
        match error {
            Some(error) if sent == 0 => Err(error),
            _ => Ok(sent),
        }
    }

    /// [`Self::poll_all_rtcp_and_send`] under the name the product uses:
    /// due NACKs and reports for every peer, not only the last one heard.
    pub fn poll_rtcp_and_send_all(&mut self, now: Instant, now_ntp: u64) -> io::Result<usize> {
        self.poll_all_rtcp_and_send(now, now_ntp)
    }

    /// Sends a keepalive to every authenticated peer whose keepalive timer
    /// is due (each peer keeps its own schedule). Returns the keepalives
    /// sent. On a send error the other peers are still served; the error is
    /// returned when nothing went out.
    pub fn poll_keepalive_all(
        &mut self,
        now: Instant,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<usize> {
        let socket = &mut self.socket;
        let mut sent = 0;
        let mut error = None;
        for (&peer, runtime) in self.peer_runtime.iter_mut() {
            if !receiver_runtime_authenticated(runtime) || !runtime.timers.poll(now).keepalive_due {
                continue;
            }
            let packet = runtime.core.build_keepalive(keepalive);
            match socket.send_packet_to(peer, &packet.bytes) {
                Ok(_) => sent += 1,
                Err(err) => error = Some(err),
            }
        }
        match error {
            Some(error) if sent == 0 => Err(error),
            _ => Ok(sent),
        }
    }

    /// Forgets every peer that has sent nothing accepted for `idle` (or
    /// nothing at all since its first datagram was refused), with its flows,
    /// NACK state and authentication. Returns the peers removed. The peer
    /// capacity ([`Self::max_peers`]) is then free for new senders.
    ///
    /// A sender that comes back after eviction starts a fresh session: its
    /// sequences are extended from scratch, so they can be far behind what
    /// was delivered before. Reset an ordered buffer fed from this
    /// receiver ([`rist_core::OrderedPayloadBuffer::reset`]) when this
    /// returns non-zero; one made with `with_deadline` also resyncs by
    /// itself.
    pub fn evict_idle_peers(&mut self, now: Instant, idle: Duration) -> usize {
        let before = self.peer_runtime.len();
        self.peer_runtime.retain(|_, runtime| {
            runtime
                .timers
                .last_peer_activity()
                .is_some_and(|last| now.saturating_duration_since(last) < idle)
        });
        if self
            .last_peer
            .is_some_and(|peer| !self.peer_runtime.contains_key(&peer))
            && self.configured_peer.is_none()
        {
            self.last_peer = None;
        }
        before - self.peer_runtime.len()
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
        let socket = &mut self.socket;
        let mut sent = Vec::new();
        let mut error = None;
        runtime
            .core
            .poll_rtcp_all_with(now, now_ntp, |_flow_id, packet| {
                match socket.send_packet_to(peer, &packet.bytes) {
                    Ok(_) => {
                        sent.push(packet);
                        true
                    }
                    Err(err) => {
                        error = Some(err);
                        false
                    }
                }
            });
        match error {
            Some(error) if sent.is_empty() => Err(error),
            _ => Ok(Some(sent)),
        }
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
        let core = match self.peer_runtime.get_mut(&peer) {
            Some(runtime) => &mut runtime.core,
            None => &mut self.core,
        };
        let socket = &mut self.socket;
        let mut first = None;
        let mut error = None;
        core.poll_rtcp_all_with(now, now_ntp, |_flow_id, packet| {
            match socket.send_packet_to(peer, &packet.bytes) {
                Ok(_) => {
                    first.get_or_insert(packet);
                    true
                }
                Err(err) => {
                    error = Some(err);
                    false
                }
            }
        });
        match error {
            Some(error) if first.is_none() => Err(error),
            _ => Ok(first),
        }
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

    pub fn socket_buffer_sizes(&self) -> io::Result<SocketBufferSizes> {
        self.socket.socket_buffer_sizes()
    }

    pub fn set_socket_buffer_sizes(
        &self,
        receive: usize,
        send: usize,
    ) -> io::Result<SocketBufferSizes> {
        self.socket.set_socket_buffer_sizes(receive, send)
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

    pub fn join_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.socket.join_multicast(group, interface, source)
    }

    pub fn leave_multicast(
        &self,
        group: IpAddr,
        interface: &NetworkInterface,
        source: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        self.socket.leave_multicast(group, interface, source)
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
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket as StdUdpSocket};
    use std::sync::{Mutex, MutexGuard};
    use std::thread;
    use std::time::Duration;

    const SRP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
    // Debug-mode 2048-bit SRP exchanges can each consume several seconds.
    // Serialize them so CPU contention does not cause test-only timeouts.
    static SRP_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_srp_test() -> MutexGuard<'static, ()> {
        SRP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// No echo requests, no extras: polls carry only NACKs and reports.
    fn static_tuning() -> RecoveryTuning {
        RecoveryTuning {
            measure_rtt: false,
            ..RecoveryTuning::librist_like()
        }
    }

    #[test]
    fn simple_receiver_counts_only_nacks_that_were_sent() {
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), 2, "receiver", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        let start = Instant::now();
        for n in 0..=250_u16 {
            let packet = encode_packet(RtpHeader::new_mpegts(2 * n, 0, 2), b"ts");
            receiver.core.accept_packet_at(&packet, start).unwrap();
        }
        // An IPv6 destination on an IPv4 socket: every send fails.
        receiver.last_rtcp_peer = Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            9,
            0,
            0,
        )));
        assert_eq!(receiver.poll_rtcp_and_send(start, 0).unwrap(), None);
        let first = start + Duration::from_millis(20);
        assert!(receiver.poll_rtcp_and_send(first, 0).is_err());
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 0);
        assert_eq!(stats.nack_entries_sent, 0);
        assert_eq!(stats.feedback_packets, 0);
        assert_eq!(stats.nack_entries_deferred, 250);

        // Once sends succeed, every hole is requested at the next poll.
        let peer = StdUdpSocket::bind(loopback_any()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        receiver.last_rtcp_peer = Some(peer.local_addr().unwrap());
        let second = first + Duration::from_millis(20);
        let bytes = receiver.poll_rtcp_and_send(second, 0).unwrap().unwrap();
        let mut requested = Vec::new();
        let mut received = 0;
        let mut buf = [0_u8; 2048];
        while received < bytes {
            let len = peer.recv(&mut buf).unwrap();
            received += len;
            requested
                .extend(rist_core::packet::rtcp::decode_nacks_from_compound(&buf[..len]).unwrap());
        }
        assert_eq!(requested, (0..250).map(|n| 2 * n + 1).collect::<Vec<_>>());
        let stats = receiver.stats();
        assert_eq!(stats.nack_packets, 2);
        assert_eq!(stats.nack_entries_sent, 250);
    }

    /// P9: a bound Simple receiver driven like the product (payload reads
    /// and `poll_rtcp_and_send` only) learns the sender's RTCP port from
    /// its RTP source and NACKs a lost packet, which the sender repairs.
    #[test]
    fn bound_simple_receiver_nacks_from_payload_reads_alone() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        assert_eq!(receiver.next_timeout(), None);
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver.local_addr().unwrap(), flow_id, 64)
                .unwrap();
        sender.set_recovery_tuning(static_tuning());
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload(b"zero", ntp, start).unwrap();
        // Sequence 1 is lost: built (so it is in the history), never sent.
        sender.build_payload(b"one", ntp, start);
        sender.send_payload(b"two", ntp, start).unwrap();

        let mut buf = [0_u8; 2048];
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while received.len() < 3 {
            while let Some((_from, payload)) = receiver.try_recv_payload(&mut buf).unwrap() {
                received.push((payload.sequence, payload.recovered));
            }
            receiver
                .poll_rtcp_and_send(Instant::now(), ntp_now())
                .unwrap();
            while sender
                .try_recv_feedback_and_retransmit(&mut buf)
                .unwrap()
                .is_some()
            {}
            assert!(
                Instant::now() < deadline,
                "no repair: received {received:?}, receiver {:?}, sender {:?}",
                receiver.stats(),
                sender.stats()
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            receiver.peer_addr(),
            Some(sender.local_addr().unwrap()),
            "the RTP peer"
        );
        assert_eq!(
            receiver.last_rtcp_peer,
            Some(sender.rtcp_local_addr().unwrap())
        );
        assert_eq!(received, vec![(0, false), (2, false), (1, true)]);
        assert!(receiver.stats().nack_packets >= 1);
        assert_eq!(sender.stats().retransmitted_packets, 1);
    }

    /// P9: one mio registration wakes for RTCP as well as RTP, and
    /// `try_recv_event` serves both sockets until both are drained.
    #[test]
    fn simple_receiver_source_wakes_for_rtcp_and_try_recv_event_reads_both() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(8);
        poll.registry()
            .register(&mut receiver, Token(7), Interest::READABLE)
            .unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver.local_addr().unwrap(), flow_id, 64)
                .unwrap();
        // An echo request alone, on the RTCP port.
        sender.send_echo_request_at(ntp_now()).unwrap();
        poll.poll(&mut events, Some(Duration::from_secs(2)))
            .unwrap();
        assert!(events.iter().any(|event| event.token() == Token(7)));

        let mut buf = [0_u8; 2048];
        let event = receiver.try_recv_event(&mut buf).unwrap();
        let Some(SimpleReceiverEvent::Rtcp { from, responses }) = event else {
            panic!("expected RTCP, got {event:?}");
        };
        assert_eq!(from, sender.rtcp_local_addr().unwrap());
        assert_eq!(responses, 1, "the echo request is answered");
        assert_eq!(receiver.try_recv_event(&mut buf).unwrap(), None);

        sender
            .send_payload(b"payload", ntp_now(), Instant::now())
            .unwrap();
        poll.poll(&mut events, Some(Duration::from_secs(2)))
            .unwrap();
        let event = receiver.try_recv_event(&mut buf).unwrap();
        assert!(
            matches!(event, Some(SimpleReceiverEvent::Payload { ref payload, .. }) if payload.sequence == 0),
            "{event:?}"
        );
        assert_eq!(receiver.try_recv_event(&mut buf).unwrap(), None);
        poll.registry().deregister(&mut receiver).unwrap();
    }

    /// Two contributors on one Main port: each gets its keepalive on its
    /// own schedule, both are NACKed, and both are evicted once idle.
    #[test]
    fn main_receiver_serves_and_evicts_every_peer() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        let receiver_addr = receiver.local_addr().unwrap();
        let mut senders = [
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap(),
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap(),
        ];
        let ntp = ntp_now();
        let start = Instant::now();
        for sender in &mut senders {
            sender.send_payload(b"zero", ntp, start).unwrap();
            sender.build_payload(b"lost", ntp, start);
            sender.send_payload(b"two", ntp, start).unwrap();
        }
        let mut buf = [0_u8; 2048];
        let mut payloads = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while payloads < 4 {
            while receiver.try_recv_payload(&mut buf).unwrap().is_some() {
                payloads += 1;
            }
            assert!(Instant::now() < deadline, "payloads: {payloads}");
        }
        assert_eq!(receiver.peer_count(), 2);
        let now = Instant::now();

        // One NACK per peer once the hole is due.
        let nack_at = now + Duration::from_millis(100);
        assert_eq!(receiver.poll_rtcp_and_send_all(nack_at, ntp).unwrap(), 2);
        for sender in &mut senders {
            let retries = loop {
                match sender.try_recv_feedback_and_retransmit(&mut buf).unwrap() {
                    Some(retries) => break retries,
                    None => {
                        assert!(Instant::now() < deadline, "no NACK");
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            };
            assert_eq!(retries.len(), 1);
            assert_eq!(retries[0].rtp_sequence, 1);
        }

        // The first poll arms each peer's timer; a keepalive interval later
        // both are due.
        let keepalive = GreKeepalive::librist_default([0; 6]);
        assert_eq!(receiver.poll_keepalive_all(now, keepalive).unwrap(), 0);
        let later = now + MainSessionConfig::default().keepalive_interval;
        assert_eq!(receiver.poll_keepalive_all(later, keepalive).unwrap(), 2);
        assert_eq!(receiver.poll_keepalive_all(later, keepalive).unwrap(), 0);
        for sender in &mut senders {
            let event = loop {
                match sender.try_recv_event(&mut buf).unwrap() {
                    Some(event) => break event,
                    None => {
                        assert!(Instant::now() < deadline, "no keepalive");
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            };
            assert!(
                matches!(event, MainSenderEvent::Keepalive { .. }),
                "{event:?}"
            );
        }

        assert_eq!(
            receiver.evict_idle_peers(now + Duration::from_millis(500), Duration::from_secs(1)),
            0
        );
        assert_eq!(
            receiver.evict_idle_peers(now + Duration::from_secs(2), Duration::from_secs(1)),
            2
        );
        assert_eq!(receiver.peer_count(), 0);
        assert_eq!(receiver.peer_addr(), None);
    }

    /// What a raw sink saw from a Main sender: data packets, SR, echo
    /// requests and keepalives.
    #[derive(Debug, Default)]
    struct SinkCounts {
        data: u64,
        sender_reports: u64,
        echo_requests: u64,
        keepalives: u64,
    }

    fn drain_sink(sink: &StdUdpSocket, counts: &mut SinkCounts) {
        let mut buf = [0u8; 2_048];
        while let Ok((len, _)) = sink.recv_from(&mut buf) {
            let datagram = &buf[..len];
            let Ok(reduced) = ReducedPacket::decode(datagram) else {
                if rist_core::packet::gre::KeepalivePacket::decode(datagram).is_ok() {
                    counts.keepalives += 1;
                }
                continue;
            };
            if !looks_like_rtcp(reduced.payload) {
                counts.data += 1;
                continue;
            }
            for packet in rist_core::packet::rtcp::decode_compound(reduced.payload).unwrap() {
                match packet {
                    rist_core::packet::rtcp::RtcpPacket::SenderReport(_) => {
                        counts.sender_reports += 1
                    }
                    rist_core::packet::rtcp::RtcpPacket::Echo(echo)
                        if echo.kind == rist_core::packet::rtcp::EchoKind::Request =>
                    {
                        counts.echo_requests += 1
                    }
                    _ => {}
                }
            }
        }
    }

    fn raw_sink() -> StdUdpSocket {
        let sink = StdUdpSocket::bind(loopback_any()).unwrap();
        sink.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        sink
    }

    /// A sender that is only ever handed data (the product's pattern) still
    /// sends its SR, echo request and (opted in) keepalive once they are
    /// due.
    #[test]
    fn main_sender_that_only_sends_still_reports_echoes_and_keeps_alive() {
        let sink = raw_sink();
        let mut sender =
            MainMioSender::connect(loopback_any(), sink.local_addr().unwrap(), 0x1122_3344, 64)
                .unwrap();
        sender.set_keepalive_mac([0; 6]);
        let ntp = ntp_now();
        let start = Instant::now();
        // The first send arms the timers; nothing else goes out. Echo
        // requests go every 100 ms (as librist), SR and keepalive every
        // second.
        sender.send_payload_meta(b"zero", ntp, start).unwrap();
        sender
            .send_payload_meta(b"one", ntp, start + Duration::from_millis(500))
            .unwrap();
        let mut counts = SinkCounts::default();
        thread::sleep(Duration::from_millis(20));
        sink.set_nonblocking(true).unwrap();
        drain_sink(&sink, &mut counts);
        assert_eq!(
            (
                counts.data,
                counts.sender_reports,
                counts.echo_requests,
                counts.keepalives
            ),
            (2, 0, 1, 0),
            "{counts:?}"
        );
        // A second later all three are due at the next send.
        sender
            .send_payload(b"two", ntp, start + Duration::from_millis(1_001))
            .unwrap();
        sender
            .send_payload_meta(b"three", ntp, start + Duration::from_millis(1_002))
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        drain_sink(&sink, &mut counts);
        assert_eq!(counts.data, 4, "{counts:?}");
        assert_eq!(counts.sender_reports, 1, "{counts:?}");
        assert_eq!(counts.echo_requests, 2, "{counts:?}");
        assert_eq!(counts.keepalives, 1, "{counts:?}");
        assert_eq!(sender.stats().sent_packets, 4);
    }

    /// An idle sender driven by `service` wakes about ten times a second
    /// (echo request every 100 ms; SR and keepalive every second), not every
    /// few hundred microseconds, and sends what is due at each wakeup.
    #[test]
    fn main_sender_service_sleeps_until_its_next_deadline() {
        let sink = raw_sink();
        sink.set_nonblocking(true).unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), sink.local_addr().unwrap(), 0x1122_3344, 64)
                .unwrap();
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let start = Instant::now();
        let mut now = start;
        let mut wakeups = 0;
        while now < start + Duration::from_secs(10) {
            let next = sender
                .service(now, ntp_now(), &mut buf)
                .unwrap()
                .expect("timers are armed");
            assert!(next > now, "deadline {next:?} not after {now:?}");
            assert!(next <= now + Duration::from_millis(100));
            wakeups += 1;
            now = next;
        }
        let mut counts = SinkCounts::default();
        thread::sleep(Duration::from_millis(20));
        drain_sink(&sink, &mut counts);
        assert!((100..=101).contains(&wakeups), "{wakeups} wakeups in 10 s");
        assert!((9..=10).contains(&counts.sender_reports), "{counts:?}");
        assert!((99..=100).contains(&counts.echo_requests), "{counts:?}");
        assert!((9..=10).contains(&counts.keepalives), "{counts:?}");
        assert_eq!(counts.data, 0);
    }

    /// Connected Main sender: a peer that is not listening (ICMP port
    /// unreachable) does not fail later sends or reads.
    #[test]
    fn connected_main_sender_ignores_a_refusing_peer() {
        let closed = StdUdpSocket::bind(loopback_any()).unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        let mut sender = MainMioSender::connect(loopback_any(), closed_addr, 2, 64).unwrap();
        assert_eq!(sender.socket.connected_peer(), Some(closed_addr));
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        for n in 0..20u32 {
            sender
                .send_payload_meta(b"nobody", 0, Instant::now())
                .unwrap();
            thread::sleep(Duration::from_millis(1));
            assert!(sender.try_recv_event(&mut buf).unwrap().is_none(), "{n}");
        }
        assert_eq!(sender.stats().sent_packets, 20);
        assert_eq!(sender.pending_send_len(), 0);
    }

    /// End to end through mio: a registered sender wakes on the receiver's
    /// NACK and `service` repairs the lost packet; between events it sleeps
    /// until `service`'s deadline.
    #[test]
    fn registered_main_sender_wakes_for_a_nack_and_repairs() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver.local_addr().unwrap(), flow_id, 64)
                .unwrap();
        sender.set_recovery_tuning(static_tuning());
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(8);
        poll.registry()
            .register(&mut sender, Token(1), Interest::READABLE)
            .unwrap();
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload_meta(b"zero", ntp, start).unwrap();
        sender.build_payload(b"lost", ntp, start);
        sender.send_payload_meta(b"two", ntp, start).unwrap();

        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut sender_buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while received.len() < 3 {
            while let Some((_from, payload)) = receiver.try_recv_payload(&mut buf).unwrap() {
                received.push((payload.sequence, payload.recovered));
            }
            receiver
                .poll_rtcp_and_send(Instant::now(), ntp_now())
                .unwrap();
            let next = sender
                .service(Instant::now(), ntp_now(), &mut sender_buf)
                .unwrap();
            let timeout = next
                .map(|at| at.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_millis(5));
            poll.poll(&mut events, Some(timeout)).unwrap();
            assert!(Instant::now() < deadline, "received {received:?}");
        }
        assert_eq!(received, vec![(0, false), (2, false), (1, true)]);
        assert_eq!(sender.stats().retransmitted_packets, 1);
        poll.registry().deregister(&mut sender).unwrap();
    }

    /// Counts the RTCP a Simple sink pair's RTCP socket received.
    fn drain_simple_rtcp(socket: &mut RtpUdpSocket, counts: &mut SinkCounts) {
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        while let Some((_, datagram)) = socket.recv_datagram(&mut buf).unwrap() {
            for packet in rist_core::packet::rtcp::decode_compound(datagram).unwrap() {
                match packet {
                    rist_core::packet::rtcp::RtcpPacket::SenderReport(_) => {
                        counts.sender_reports += 1
                    }
                    rist_core::packet::rtcp::RtcpPacket::Echo(echo)
                        if echo.kind == rist_core::packet::rtcp::EchoKind::Request =>
                    {
                        counts.echo_requests += 1
                    }
                    _ => {}
                }
            }
        }
    }

    /// Simple sender: `send_payload` sends the SR/echo request once due, and
    /// an idle sender driven by `service` wakes about ten times a second.
    #[test]
    fn simple_sender_drives_its_rtcp_from_sends_and_from_service() {
        let (mut sink_rtp, mut sink_rtcp) = bind_simple_pair(loopback_any(), 2, false).unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), sink_rtp.local_addr().unwrap(), 2, 64)
                .unwrap();
        assert_eq!(
            sender.rtp_socket.connected_peer(),
            Some(sink_rtp.local_addr().unwrap())
        );
        let ntp = ntp_now();
        let start = Instant::now();
        assert_eq!(sender.send_payload_meta(b"zero", ntp, start).unwrap(), 0);
        let owned = sender
            .send_payload(b"one", ntp, start + Duration::from_millis(1_001))
            .unwrap();
        assert_eq!((owned.sequence, &owned.bytes[12..]), (1, &b"one"[..]));
        thread::sleep(Duration::from_millis(20));
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut data = Vec::new();
        while let Some((_, datagram)) = sink_rtp.recv_datagram(&mut buf).unwrap() {
            data.push(datagram.to_vec());
        }
        assert_eq!(data.len(), 2);
        assert_eq!(data[1], owned.bytes);
        let mut counts = SinkCounts::default();
        drain_simple_rtcp(&mut sink_rtcp, &mut counts);
        assert_eq!(
            (counts.sender_reports, counts.echo_requests),
            (1, 1),
            "{counts:?}"
        );

        let mut now = start + Duration::from_millis(1_001);
        let end = now + Duration::from_secs(5);
        let mut wakeups = 0;
        while now < end {
            let next = sender.service(now, ntp, &mut buf).unwrap().unwrap();
            assert!(next > now && next <= now + Duration::from_millis(100));
            wakeups += 1;
            now = next;
        }
        assert!((50..=51).contains(&wakeups), "{wakeups}");
        thread::sleep(Duration::from_millis(20));
        drain_simple_rtcp(&mut sink_rtcp, &mut counts);
        assert!((5..=6).contains(&counts.sender_reports), "{counts:?}");
        assert!((50..=51).contains(&counts.echo_requests), "{counts:?}");
    }

    /// A registered Simple sender wakes for a NACK on its RTCP port and
    /// `service` repairs.
    #[test]
    fn registered_simple_sender_wakes_for_a_nack_and_repairs() {
        let flow_id = 0x1122_3344;
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "receiver", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver.local_addr().unwrap(), flow_id, 64)
                .unwrap();
        sender.set_recovery_tuning(static_tuning());
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(8);
        poll.registry()
            .register(&mut sender, Token(3), Interest::READABLE)
            .unwrap();
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload_meta(b"zero", ntp, start).unwrap();
        sender.build_payload(b"one", ntp, start);
        sender.send_payload_meta(b"two", ntp, start).unwrap();
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut sender_buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while received.len() < 3 {
            while let Some(event) = receiver.try_recv_event(&mut buf).unwrap() {
                if let SimpleReceiverEvent::Payload { payload, .. } = event {
                    received.push((payload.sequence, payload.recovered));
                }
            }
            receiver
                .poll_rtcp_and_send(Instant::now(), ntp_now())
                .unwrap();
            let next = sender
                .service(Instant::now(), ntp_now(), &mut sender_buf)
                .unwrap();
            let timeout = next
                .map(|at| at.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_millis(5));
            poll.poll(&mut events, Some(timeout)).unwrap();
            assert!(Instant::now() < deadline, "received {received:?}");
        }
        assert_eq!(received, vec![(0, false), (2, false), (1, true)]);
        assert_eq!(sender.stats().retransmitted_packets, 1);
    }

    /// Multi-peer sender: data alone drives the SR/echo and every peer's
    /// keepalive; `service` returns the next deadline.
    #[test]
    fn multi_sender_drives_its_timers_from_sends_and_service() {
        let sinks = [raw_sink(), raw_sink()];
        let mut sender = MainMioMultiSender::bind(loopback_any(), 2, 64).unwrap();
        sender.set_keepalive_mac([0; 6]);
        for sink in &sinks {
            sink.set_nonblocking(true).unwrap();
            sender.add_peer(sink.local_addr().unwrap(), 1).unwrap();
        }
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload(b"zero", ntp, start).unwrap();
        sender
            .send_payload(b"one", ntp, start + Duration::from_millis(1_001))
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        let mut total = SinkCounts::default();
        for sink in &sinks {
            let mut counts = SinkCounts::default();
            drain_sink(sink, &mut counts);
            assert_eq!(counts.keepalives, 1, "{counts:?}");
            total.data += counts.data;
            total.sender_reports += counts.sender_reports;
            total.echo_requests += counts.echo_requests;
        }
        assert!(total.data >= 2, "{total:?}");
        assert!(total.sender_reports >= 1, "{total:?}");
        assert!(total.echo_requests >= 1, "{total:?}");

        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let now = start + Duration::from_millis(1_050);
        let next = sender.service(now, ntp, &mut buf).unwrap().unwrap();
        assert!(next > now && next <= now + Duration::from_millis(100));
        assert_eq!(sender.next_timeout(), Some(next));
    }

    /// The MACs of the keepalives a raw sink received.
    fn sink_keepalive_macs(sink: &StdUdpSocket) -> Vec<[u8; 6]> {
        let mut buf = [0u8; 2_048];
        let mut macs = Vec::new();
        while let Ok((len, _)) = sink.recv_from(&mut buf) {
            if let Ok(packet) = rist_core::packet::gre::KeepalivePacket::decode(&buf[..len]) {
                macs.push(packet.keepalive.mac);
            }
        }
        macs
    }

    /// Without opting in, `send_payload` sends no keepalive and leaves the
    /// due one to the caller's own `poll_session_and_send_keepalive`; with
    /// `set_auto_keepalive` it sends the caller's keepalive itself.
    #[test]
    fn main_sender_keepalives_from_sends_are_opt_in() {
        let sink = raw_sink();
        sink.set_nonblocking(true).unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), sink.local_addr().unwrap(), 0x1122_3344, 64)
                .unwrap();
        let custom = GreKeepalive {
            mac: [1, 2, 3, 4, 5, 6],
            capabilities1: 0,
            capabilities2: 0,
            json: b"{}",
        };
        let ntp = ntp_now();
        let start = Instant::now();
        assert!(sender
            .poll_session_and_send_keepalive(start, custom)
            .unwrap()
            .keepalive
            .is_none());
        sender.send_payload_meta(b"zero", ntp, start).unwrap();
        sender
            .send_payload_meta(b"one", ntp, start + Duration::from_millis(1_001))
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(sink_keepalive_macs(&sink).is_empty());
        let poll = sender
            .poll_session_and_send_keepalive(start + Duration::from_millis(1_002), custom)
            .unwrap();
        assert!(poll.poll.keepalive_due);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(sink_keepalive_macs(&sink), vec![[1, 2, 3, 4, 5, 6]]);

        sender.set_auto_keepalive(custom);
        sender
            .send_payload_meta(b"two", ntp, start + Duration::from_millis(2_002))
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(sink_keepalive_macs(&sink), vec![[1, 2, 3, 4, 5, 6]]);
        sender.set_keepalive_mac([9; 6]);
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        sender
            .service(start + Duration::from_millis(3_002), ntp, &mut buf)
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(sink_keepalive_macs(&sink), vec![[9; 6]]);
        assert_eq!(
            sender.auto_keepalive.as_ref().map(|k| k.json.as_slice()),
            Some(&b"{}"[..])
        );
    }

    /// While SRP is not authenticated (a peer that went quiet is being
    /// re-authenticated) the SR/echo and repair timers stand still, so
    /// `service` must not return their past deadlines: it sleeps until the
    /// keepalive instead of spinning.
    #[test]
    fn main_sender_service_does_not_spin_while_reauthenticating() {
        let sink = raw_sink();
        sink.set_nonblocking(true).unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), sink.local_addr().unwrap(), 0x1122_3344, 64)
                .unwrap();
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload_meta(b"zero", ntp, start).unwrap();
        assert!(sender.next_timeout().is_some());
        // The peer was last heard at `start`; SRP is configured but the
        // session is not (yet, again) authenticated.
        sender.enable_srp_client("user", "password");
        sender.observe_peer_activity(start);
        assert!(!sender.srp_authenticated());
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut now = start + Duration::from_millis(500);
        let end = start + Duration::from_secs(10);
        let mut wakeups = 0;
        while now < end {
            let next = sender
                .service(now, ntp, &mut buf)
                .unwrap()
                .expect("keepalive timer is armed");
            assert!(next > now, "deadline {next:?} not after {now:?}");
            assert!(sender.next_timeout().is_some_and(|at| at > now));
            wakeups += 1;
            now = next;
        }
        assert!((9..=11).contains(&wakeups), "{wakeups} wakeups");
        // It did start re-authenticating after the session timeout.
        assert!(sender.last_reauthentication.is_some());
    }

    /// A bonded peer that re-authenticates holds up neither the SR/echo to
    /// the others nor `service`'s deadline.
    #[test]
    fn multi_sender_reports_to_authenticated_peers_while_one_reauthenticates() {
        let sinks = [raw_sink(), raw_sink()];
        let mut sender = MainMioMultiSender::bind(loopback_any(), 2, 64).unwrap();
        for sink in &sinks {
            sink.set_nonblocking(true).unwrap();
            sender.add_peer(sink.local_addr().unwrap(), 1).unwrap();
        }
        let ntp = ntp_now();
        let start = Instant::now();
        sender.send_payload(b"zero", ntp, start).unwrap();
        thread::sleep(Duration::from_millis(20));
        for sink in &sinks {
            drain_sink(sink, &mut SinkCounts::default());
        }
        // Peer 1 restarts SRP (as after a timeout); peer 0 stays up.
        sender.peer_runtime[1].srp = Some(EapSrpClientSession::new("user", "password"));
        assert_eq!(sender.peer_srp_authenticated(0), Some(true));
        assert_eq!(sender.peer_srp_authenticated(1), Some(false));

        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let mut now = start + Duration::from_millis(150);
        let end = start + Duration::from_millis(2_150);
        let mut wakeups = 0;
        while now < end {
            let next = sender.service(now, ntp, &mut buf).unwrap().unwrap();
            assert!(next > now, "deadline {next:?} not after {now:?}");
            wakeups += 1;
            now = next;
        }
        assert!((19..=22).contains(&wakeups), "{wakeups} wakeups");
        thread::sleep(Duration::from_millis(20));
        let mut up = SinkCounts::default();
        drain_sink(&sinks[0], &mut up);
        let mut down = SinkCounts::default();
        drain_sink(&sinks[1], &mut down);
        assert!(up.echo_requests >= 19, "{up:?}");
        assert!(up.sender_reports >= 1, "{up:?}");
        assert_eq!(
            (down.echo_requests, down.sender_reports),
            (0, 0),
            "{down:?}"
        );
        // Data to the healthy peer does not run the timers on every send.
        sender.set_peer_weight(1, 0);
        sender.send_payload(b"one", ntp, now).unwrap();
        assert!(sender.next_timer_at.is_some_and(|at| at > now));
    }

    /// `service` reads past datagrams it ignores (an unknown source), so
    /// what is queued behind them is served now, not at the next wakeup.
    #[test]
    fn multi_sender_service_reads_past_an_ignored_datagram() {
        let peer = StdUdpSocket::bind(loopback_any()).unwrap();
        let stray = StdUdpSocket::bind(loopback_any()).unwrap();
        let mut sender = MainMioMultiSender::bind(loopback_any(), 2, 64).unwrap();
        sender.add_peer(peer.local_addr().unwrap(), 1).unwrap();
        let to = sender.local_addr().unwrap();
        let keepalive = MainSenderCore::new(7, 8)
            .build_keepalive(GreKeepalive::librist_default([0; 6]))
            .bytes;
        stray.send_to(&keepalive, to).unwrap();
        peer.send_to(&keepalive, to).unwrap();
        thread::sleep(Duration::from_millis(20));
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        sender.service(Instant::now(), ntp_now(), &mut buf).unwrap();
        assert!(sender.peer_last_activity(0).is_some());
        assert!(sender.socket.recv_datagram(&mut buf).unwrap().is_none());
    }

    /// The Simple sender reads past feedback from an address that is not
    /// its peer.
    #[test]
    fn simple_sender_service_reads_past_feedback_from_another_address() {
        let (sink_rtp, _sink_rtcp) = bind_simple_pair(loopback_any(), 2, false).unwrap();
        let (_stray_rtp, stray_rtcp) = bind_simple_pair(loopback_any(), 4, false).unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), sink_rtp.local_addr().unwrap(), 2, 64)
                .unwrap();
        let to = sender.rtcp_socket.local_addr().unwrap();
        let mut stray = stray_rtcp;
        stray
            .send_packet_to(to, b"\x80\xc9\x00\x01\0\0\0\x04")
            .unwrap();
        stray
            .send_packet_to(to, b"\x80\xc9\x00\x01\0\0\0\x04")
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        sender.service(Instant::now(), ntp_now(), &mut buf).unwrap();
        assert!(sender
            .rtcp_socket
            .recv_datagram(&mut buf)
            .unwrap()
            .is_none());
    }

    /// Stopped at the read limit with datagrams left, `service` asks to be
    /// called again at once: an edge-triggered source would not wake it.
    #[test]
    fn service_asks_to_run_again_when_it_stops_at_the_read_limit() {
        let mut sender = MainMioSender::listen(loopback_any(), 2, 64).unwrap();
        let to = sender.local_addr().unwrap();
        let flood = StdUdpSocket::bind(loopback_any()).unwrap();
        for _ in 0..SERVICE_READ_LIMIT + 50 {
            flood.send_to(b"not rist", to).unwrap();
        }
        thread::sleep(Duration::from_millis(20));
        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let now = Instant::now();
        assert_eq!(sender.service(now, ntp_now(), &mut buf).unwrap(), Some(now));
        let later = Instant::now();
        assert_eq!(sender.service(later, ntp_now(), &mut buf).unwrap(), None);
        assert!(sender.socket.recv_datagram(&mut buf).unwrap().is_none());
    }

    fn loopback_any() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    fn ipv6_loopback_any() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
    }

    fn loopback_interface() -> NetworkInterface {
        #[cfg(target_os = "macos")]
        {
            NetworkInterface::Name("lo0".to_string())
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            NetworkInterface::Name("lo".to_string())
        }
        #[cfg(not(unix))]
        {
            NetworkInterface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
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

    #[cfg(unix)]
    #[test]
    fn icmp_errors_reported_for_earlier_datagrams_are_recognised() {
        for errno in [
            libc::ECONNREFUSED,
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::EHOSTDOWN,
            libc::ENOPROTOOPT,
            libc::EOPNOTSUPP,
        ] {
            assert!(
                is_reported_icmp_error(&io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
        assert!(is_reported_icmp_error(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        for errno in [libc::EMSGSIZE, libc::ENOBUFS, libc::EAGAIN, libc::EBADF] {
            assert!(
                !is_reported_icmp_error(&io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
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
        let _srp_test = lock_srp_test();
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
        let deadline = Instant::now() + SRP_HANDSHAKE_TIMEOUT;
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
        sender.set_recovery_tuning(without_startup_copy());

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
        // About NACK isolation: no echo requests in the polls.
        receiver.set_recovery_tuning(static_tuning());
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
        let _srp_test = lock_srp_test();
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
        let deadline = Instant::now() + SRP_HANDSHAKE_TIMEOUT;
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
    fn simple_and_main_profiles_send_over_ipv6() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));

        let mut simple_receiver =
            SimpleMioReceiver::bind(ipv6_loopback_any(), flow_id, "ipv6", NackMode::Range).unwrap();
        let mut simple_sender = SimpleMioSender::connect(
            ipv6_loopback_any(),
            simple_receiver.local_addr().unwrap(),
            flow_id,
            64,
        )
        .unwrap();
        simple_sender
            .send_payload(b"simple-ipv6", ntp, Instant::now())
            .unwrap();
        let mut simple_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((from, payload)) =
                simple_receiver.try_recv_payload(&mut simple_buf).unwrap()
            {
                assert!(from.is_ipv6());
                assert_eq!(payload.payload, b"simple-ipv6");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the Simple IPv6 payload"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let mut main_receiver =
            MainMioReceiver::bind(ipv6_loopback_any(), flow_id, "ipv6", NackMode::Range).unwrap();
        let mut main_sender = MainMioSender::connect(
            ipv6_loopback_any(),
            main_receiver.local_addr().unwrap(),
            flow_id,
            64,
        )
        .unwrap();
        main_sender
            .send_payload(b"main-ipv6", ntp, Instant::now())
            .unwrap();
        let mut main_buf = [0u8; 1500];
        let payload = recv_main_payload_eventually(&mut main_receiver, &mut main_buf);
        assert_eq!(payload.payload, b"main-ipv6");
    }

    #[test]
    fn receivers_expose_mio_payload_readiness() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));

        let mut simple_receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "ready", NackMode::Range).unwrap();
        let mut simple_poll = mio::Poll::new().unwrap();
        simple_poll
            .registry()
            .register(&mut simple_receiver, Token(7), Interest::READABLE)
            .unwrap();
        let mut simple_sender = SimpleMioSender::connect(
            loopback_any(),
            simple_receiver.local_addr().unwrap(),
            flow_id,
            64,
        )
        .unwrap();
        simple_sender
            .send_payload(b"simple-ready", ntp, Instant::now())
            .unwrap();
        let mut simple_events = mio::Events::with_capacity(4);
        simple_poll
            .poll(&mut simple_events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(simple_events
            .iter()
            .any(|event| event.token() == Token(7) && event.is_readable()));

        let mut main_receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "ready", NackMode::Range).unwrap();
        let mut main_poll = mio::Poll::new().unwrap();
        main_poll
            .registry()
            .register(&mut main_receiver, Token(9), Interest::READABLE)
            .unwrap();
        let mut main_sender = MainMioSender::connect(
            loopback_any(),
            main_receiver.local_addr().unwrap(),
            flow_id,
            64,
        )
        .unwrap();
        main_sender
            .send_payload(b"main-ready", ntp, Instant::now())
            .unwrap();
        let mut main_events = mio::Events::with_capacity(4);
        main_poll
            .poll(&mut main_events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(main_events
            .iter()
            .any(|event| event.token() == Token(9) && event.is_readable()));
    }

    #[test]
    fn receiver_callers_discover_sender_listeners_over_ipv6() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));

        let mut simple_sender = SimpleMioSender::listen(ipv6_loopback_any(), flow_id, 64).unwrap();
        let simple_sender_addr = simple_sender.local_addr().unwrap();
        let mut simple_receiver = SimpleMioReceiver::connect(
            ipv6_loopback_any(),
            simple_sender_addr,
            flow_id,
            "ipv6-caller",
            NackMode::Range,
        )
        .unwrap();
        simple_receiver.send_feedback().unwrap().unwrap();
        let mut simple_control_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while simple_sender.peer_addr().is_none() {
            simple_sender
                .try_recv_feedback_and_retransmit(&mut simple_control_buf)
                .unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out discovering the Simple IPv6 caller"
            );
            thread::sleep(Duration::from_millis(1));
        }
        simple_sender
            .send_payload(b"simple-ipv6-reverse", ntp, Instant::now())
            .unwrap();
        let mut simple_payload_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((_from, payload)) = simple_receiver
                .try_recv_payload(&mut simple_payload_buf)
                .unwrap()
            {
                assert_eq!(payload.payload, b"simple-ipv6-reverse");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the reverse Simple IPv6 payload"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let mut main_sender = MainMioSender::listen(ipv6_loopback_any(), flow_id, 64).unwrap();
        let main_sender_addr = main_sender.local_addr().unwrap();
        let mut main_receiver = MainMioReceiver::connect(
            ipv6_loopback_any(),
            main_sender_addr,
            flow_id,
            "ipv6-caller",
            NackMode::Range,
        )
        .unwrap();
        main_receiver
            .send_keepalive_to(
                main_sender_addr,
                GreKeepalive::librist_default([1, 2, 3, 4, 5, 6]),
            )
            .unwrap();
        let mut main_control_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while main_sender.peer_addr().is_none() {
            main_sender.try_recv_event(&mut main_control_buf).unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out discovering the Main IPv6 caller"
            );
            thread::sleep(Duration::from_millis(1));
        }
        main_sender
            .send_payload(b"main-ipv6-reverse", ntp, Instant::now())
            .unwrap();
        let mut main_payload_buf = [0u8; 1500];
        let payload = recv_main_payload_eventually(&mut main_receiver, &mut main_payload_buf);
        assert_eq!(payload.payload, b"main-ipv6-reverse");
    }

    #[test]
    fn constructors_reject_mixed_ip_address_families() {
        let ipv4 = loopback_any();
        let ipv6 = ipv6_loopback_any();

        let error = match SimpleMioSender::connect(ipv4, ipv6, 2, 64) {
            Ok(_) => panic!("mixed-family Simple sender unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let error = match SimpleMioReceiver::connect(ipv4, ipv6, 1, "mixed-family", NackMode::Range)
        {
            Ok(_) => panic!("mixed-family Simple receiver unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let error = match MainMioSender::connect(ipv4, ipv6, 2, 64) {
            Ok(_) => panic!("mixed-family Main sender unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let error = match MainMioReceiver::connect(ipv4, ipv6, 1, "mixed-family", NackMode::Range) {
            Ok(_) => panic!("mixed-family Main receiver unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut sender = MainMioMultiSender::bind(ipv4, 1, 64).unwrap();
        let error = sender.add_peer(ipv6, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(sender.peers().is_empty());
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
    fn rtp_udp_socket_configures_the_librist_buffer_floor() {
        let socket = RtpUdpSocket::bind(loopback_any(), 1).unwrap();
        let sizes = socket.socket_buffer_sizes().unwrap();

        assert!(sizes.receive >= MINIMUM_SOCKET_BUFFER_SIZE);
        assert!(sizes.send >= MINIMUM_SOCKET_BUFFER_SIZE);
        assert_eq!(
            socket
                .set_socket_buffer_sizes(MINIMUM_SOCKET_BUFFER_SIZE - 1, i32::MAX as usize)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rtp_udp_socket_reports_and_discards_truncated_datagrams() {
        let mut receiver = RtpUdpSocket::bind(loopback_any(), 1).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = StdUdpSocket::bind(loopback_any()).unwrap();
        sender.send_to(&[0x5a; 128], receiver_addr).unwrap();

        let mut small = [0u8; 32];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.recv_datagram(&mut small) {
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    let truncated = error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<TruncatedDatagram>())
                        .expect("truncation must use the typed error");
                    assert_eq!(truncated.peer, sender.local_addr().unwrap());
                    assert_eq!(truncated.datagram_size, 128);
                    assert_eq!(truncated.buffer_capacity, small.len());
                    break;
                }
                Ok(None) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for the oversized datagram"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(Some(_)) => panic!("oversized datagram was accepted"),
            }
        }

        sender.send_to(b"complete", receiver_addr).unwrap();
        let mut complete = [0u8; 32];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.recv_datagram(&mut complete).unwrap() {
                Some((from, payload)) => {
                    assert_eq!(from, sender.local_addr().unwrap());
                    assert_eq!(payload, b"complete");
                    break;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for the complete datagram"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rtp_udp_socket_rejects_datagrams_above_the_librist_limit() {
        let mut receiver = RtpUdpSocket::bind(loopback_any(), 1).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = StdUdpSocket::bind(loopback_any()).unwrap();
        sender
            .send_to(&vec![0x5a; MAX_RIST_DATAGRAM_SIZE + 512], receiver_addr)
            .unwrap();

        let mut buf = vec![0u8; SAFE_RECEIVE_CAPACITY];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match receiver.recv_datagram(&mut buf) {
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    let oversized = error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<OversizedDatagram>())
                        .expect("oversized input must use the typed error");
                    if let Some(peer) = oversized.peer {
                        assert_eq!(peer, sender.local_addr().unwrap());
                    }
                    if let Some(size) = oversized.observed_size {
                        assert!(size > MAX_RIST_DATAGRAM_SIZE);
                    }
                    break;
                }
                Ok(None) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for the oversized datagram"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(Some(_)) => panic!("oversized datagram was accepted"),
            }
        }
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
    fn simple_profile_poll_sends_every_due_nack_packet() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        receiver.set_recovery_tuning(static_tuning());
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver_addr, flow_id, 2048).unwrap();

        // The receiver learns its RTCP peer from the sender's echo request.
        sender.send_echo_request_at(ntp).unwrap();
        let mut rx_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while receiver
            .try_recv_rtcp_and_respond(&mut rx_buf)
            .unwrap()
            .is_none()
        {
            assert!(Instant::now() < deadline, "timed out waiting for the echo");
            thread::sleep(Duration::from_millis(1));
        }

        let now = Instant::now();
        for index in 0..=1_000_u32 {
            let packet = sender.build_payload(&index.to_be_bytes(), ntp, now);
            if index % 2 == 0 {
                sender.send_outbound(&packet).unwrap();
                recv_payload_eventually(&mut receiver, &mut rx_buf);
            }
        }
        assert_eq!(receiver.core.missing_sequences().len(), 500);

        let polled = Instant::now();
        assert_eq!(receiver.poll_rtcp_and_send(polled, ntp).unwrap(), None);
        let sent = receiver
            .poll_rtcp_and_send(polled + Duration::from_millis(20), ntp)
            .unwrap()
            .unwrap();
        // 200 + 200 + 100 single-hole records, each packet with RR + SDES.
        assert!(sent > 2_000, "{sent} bytes");
        assert_eq!(receiver.stats().nack_packets, 3);

        let mut feedback_buf = [0u8; 1500];
        let mut retries = Vec::new();
        while retries.len() < 500 {
            retries.extend(recv_feedback_eventually(&mut sender, &mut feedback_buf));
        }
        assert_eq!(
            retries
                .iter()
                .map(|retry| retry.sequence)
                .collect::<Vec<_>>(),
            (0..500).map(|n| 2 * n + 1).collect::<Vec<_>>()
        );
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

    #[test]
    fn simple_profile_receives_ipv4_asm_payload_on_named_interface() {
        let flow_id = 0x1122_3344;
        let interface = loopback_interface();
        let mut receiver = SimpleMioReceiver::bind_reuse(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            flow_id,
            "rust",
            NackMode::Range,
        )
        .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let group = Ipv4Addr::new(239, 255, (port >> 8) as u8, port as u8);
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(group, port));
        receiver
            .join_multicast(IpAddr::V4(group), &interface, None)
            .unwrap();

        let mut sender =
            SimpleMioSender::connect(loopback_any(), multicast_addr, flow_id, 64).unwrap();
        sender
            .configure_multicast(&interface, Some(1), true)
            .unwrap();

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

        receiver
            .leave_multicast(IpAddr::V4(group), &interface, None)
            .unwrap();
    }

    #[test]
    fn ipv4_ssm_accepts_the_configured_source() {
        let interface = NetworkInterface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut receiver = RtpUdpSocket::bind_reuse(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            1,
        )
        .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let group = Ipv4Addr::new(232, 255, (port >> 8) as u8, port as u8);
        let destination = SocketAddr::V4(SocketAddrV4::new(group, port));
        receiver
            .join_multicast(IpAddr::V4(group), &interface, Some(Ipv4Addr::LOCALHOST))
            .unwrap();

        let mut buf = [0u8; 64];
        let mut accepted = RtpUdpSocket::bind(loopback_any(), 3).unwrap();
        accepted.set_multicast_interface(&interface).unwrap();
        accepted.send_packet_to(destination, b"accepted").unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some((from, payload)) = receiver.recv_datagram(&mut buf).unwrap() {
                assert_eq!(from.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(payload, b"accepted");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the accepted SSM source"
            );
            thread::sleep(Duration::from_millis(1));
        }

        receiver
            .leave_multicast(IpAddr::V4(group), &interface, Some(Ipv4Addr::LOCALHOST))
            .unwrap();
    }

    #[test]
    fn main_profile_receives_ipv6_asm_payload_on_named_interface() {
        let flow_id = 0x1122_3344;
        let interface = loopback_interface();
        let resolved = resolve_network_interface(&interface).unwrap();
        let mut receiver = MainMioReceiver::bind_reuse(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            flow_id,
            "rust",
            NackMode::Range,
        )
        .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let group = "ff02::114".parse::<Ipv6Addr>().unwrap();
        let destination = SocketAddr::V6(SocketAddrV6::new(group, port, 0, resolved.index));
        receiver
            .join_multicast(IpAddr::V6(group), &interface, None)
            .unwrap();

        let mut sender =
            MainMioSender::connect(ipv6_loopback_any(), destination, flow_id, 64).unwrap();
        sender
            .configure_multicast(&interface, Some(1), true)
            .unwrap();
        for _ in 0..5 {
            sender
                .send_payload(
                    b"ipv6-multicast",
                    ntp_from_unix_duration(Duration::from_secs(1)),
                    Instant::now(),
                )
                .unwrap();
            thread::sleep(Duration::from_millis(10));
        }

        let mut buf = [0u8; 1500];
        let received = recv_main_payload_eventually(&mut receiver, &mut buf);
        assert_eq!(received.payload, b"ipv6-multicast");
        receiver
            .leave_multicast(IpAddr::V6(group), &interface, None)
            .unwrap();
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
    fn main_profile_receiver_measures_rtt_through_sender_echo_responses() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        assert_eq!(receiver.next_timeout(), None, "idle before any data");

        let first = sender.build_payload(b"first", ntp, Instant::now());
        sender.send_outbound(&first).unwrap();
        let mut rx_buf = [0u8; 1500];
        recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        // The first echo request is due at once.
        assert!(receiver.next_timeout().unwrap() <= Instant::now());
        assert_eq!(
            receiver
                .poll_all_rtcp_and_send(Instant::now(), ntp_now())
                .unwrap(),
            1
        );

        // The sender answers inside its feedback handling.
        let mut tx_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        while sender.stats().echo_responses == 0 {
            sender.try_recv_event(&mut tx_buf).unwrap();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the echo request"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            receiver.try_recv_event(&mut rx_buf).unwrap();
            let stats = receiver
                .peer_flow_stats(sender.local_addr().unwrap(), flow_id)
                .unwrap();
            if stats.rtt_samples_echo == 1 {
                assert!(stats.rtt_micros.unwrap() < 1_000_000);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the echo response"
            );
            thread::sleep(Duration::from_millis(1));
        }
        // Idle: nothing due before the next echo request (100 ms).
        let next = receiver.next_timeout().unwrap();
        assert!(next > Instant::now() + Duration::from_millis(50));
    }

    #[test]
    fn main_sender_serves_feedback_from_its_send_path() {
        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 1_024).unwrap();
        sender.set_recovery_tuning(without_startup_copy());
        let sender_addr = sender.local_addr().unwrap();
        let now = Instant::now();
        let first = sender.build_payload(b"first", ntp, now);
        let _lost = sender.build_payload(b"lost", ntp, now);
        let third = sender.build_payload(b"third", ntp, now);
        sender.send_outbound(&first).unwrap();
        sender.send_outbound(&third).unwrap();
        let mut rx_buf = [0u8; 1500];
        recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        // The NACK and an OOB packet reach the sender while it is in the
        // middle of a long burst and never calls service().
        receiver.send_feedback_to(sender_addr).unwrap();
        receiver.send_oob_to(sender_addr, b"side channel").unwrap();
        thread::sleep(Duration::from_millis(5));
        for _ in 0..INLINE_SERVICE_EVERY {
            sender
                .send_payload_meta(b"burst", ntp, Instant::now())
                .unwrap();
        }
        assert_eq!(sender.stats().retransmitted_packets, 1, "repaired inline");
        // The OOB event waits for try_recv_event, and the sender asks to be
        // called for it.
        assert!(sender.next_timeout().unwrap() <= Instant::now());
        let mut tx_buf = [0u8; 1500];
        match sender.try_recv_event(&mut tx_buf).unwrap() {
            Some(MainSenderEvent::Oob { packet, .. }) => {
                assert_eq!(packet.payload, b"side channel")
            }
            other => panic!("expected the OOB event, got {other:?}"),
        }
        assert!(sender.try_recv_event(&mut tx_buf).unwrap().is_none());
        let mut recovered = false;
        for _ in 0..=INLINE_SERVICE_EVERY {
            let payload = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
            if payload.recovered {
                assert_eq!(payload.payload, b"lost");
                recovered = true;
                break;
            }
        }
        assert!(recovered);
    }

    #[test]
    fn main_sender_sends_duplicate_repairs_when_drained_and_reports_its_deadline() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        assert_eq!(sender.next_timeout(), None, "nothing armed yet");
        sender.poll_rtcp_and_send(now, ntp).unwrap();
        let idle = sender.next_timeout().unwrap();
        assert!(idle > now && idle <= now + Duration::from_millis(100));

        let first = sender.build_payload(b"first", ntp, now);
        let _lost = sender.build_payload(b"lost", ntp, now);
        let third = sender.build_payload(b"third", ntp, now);
        sender.send_outbound(&first).unwrap();
        sender.send_outbound(&third).unwrap();
        let mut rx_buf = [0u8; 1500];
        recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        recv_main_payload_eventually(&mut receiver, &mut rx_buf);
        // The first packet goes out a second time 1 ms later; the receiver
        // has it already.
        assert!(sender.next_timeout().unwrap() <= now + Duration::from_millis(1));
        thread::sleep(Duration::from_millis(2));
        assert_eq!(sender.poll_repairs_and_send(Instant::now()).unwrap(), 1);
        assert!(recv_main_payload_eventually(&mut receiver, &mut rx_buf).duplicate);

        // Two requests for the same hole, beyond the sender's spacing: the
        // second repair is sent twice.
        let mut tx_buf = [0u8; 1500];
        receiver.send_feedback_to(sender_addr).unwrap();
        assert_eq!(
            recv_main_feedback_eventually(&mut sender, &mut tx_buf).len(),
            1
        );
        thread::sleep(Duration::from_millis(10));
        receiver.send_feedback_to(sender_addr).unwrap();
        assert_eq!(
            recv_main_feedback_eventually(&mut sender, &mut tx_buf).len(),
            1
        );
        let due = sender.next_timeout().unwrap();
        assert!(due <= Instant::now() + Duration::from_millis(1));
        thread::sleep(Duration::from_millis(2));
        // A drained receive sends it.
        assert!(sender.try_recv_event(&mut tx_buf).unwrap().is_none());
        assert_eq!(sender.stats().duplicate_repairs, 2);

        let mut copies = Vec::new();
        while copies.len() < 3 {
            let payload = recv_main_payload_eventually(&mut receiver, &mut rx_buf);
            copies.push((payload.recovered, payload.duplicate));
        }
        assert_eq!(copies, vec![(true, false), (false, true), (false, true)]);
    }

    #[test]
    fn main_profile_streams_needletail_mpegts_with_full_receive_headroom() {
        const PACKETS: u64 = 64;

        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut payload = Vec::with_capacity(7 * TS_PACKET_SIZE);
        for pid in 0x0100..0x0107 {
            payload.extend_from_slice(&ts_packet(pid, b"needletail"));
        }
        assert_eq!(payload.len(), 1_316);

        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "needletail", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 8_192).unwrap();
        let mut receive = vec![0u8; 65_536];

        for _ in 0..PACKETS {
            sender.send_payload(&payload, ntp, Instant::now()).unwrap();
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received_packets = 0;
        while received_packets < PACKETS {
            match receiver.try_recv_payload(&mut receive).unwrap() {
                Some((_from, received)) => {
                    assert_eq!(received.payload, payload);
                    received_packets += 1;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for the Needletail payload burst"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }

        let stats = receiver.stats();
        assert_eq!(stats.received_packets, PACKETS);
        assert_eq!(stats.received_bytes, PACKETS * 1_316);
        assert!(receiver
            .socket
            .receive_scratch
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn main_profile_sender_sustains_needletail_mpegts_to_a_raw_udp_sink() {
        const PACKETS: u64 = 8_448;
        const PACKETS_PER_BURST: u64 = 8;

        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut payload = Vec::with_capacity(7 * TS_PACKET_SIZE);
        for pid in 0x0100..0x0107 {
            payload.extend_from_slice(&ts_packet(pid, b"needletail-raw-sink"));
        }

        let receiver = StdUdpSocket::bind(loopback_any()).unwrap();
        SockRef::from(&receiver)
            .set_recv_buffer_size(16 * 1024 * 1024)
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let receiver_thread = thread::spawn(move || {
            let mut buf = [0u8; 2_048];
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut received_packets = 0;
            while received_packets < PACKETS {
                match receiver.recv_from(&mut buf) {
                    Ok((len, _)) => {
                        // A sender that only sends still sends its
                        // keepalives and SR/echo requests: skip them.
                        let Ok(reduced) = ReducedPacket::decode(&buf[..len]) else {
                            continue;
                        };
                        if looks_like_rtcp(reduced.payload) {
                            continue;
                        }
                        let rtp = RtpPacket::decode(reduced.payload).unwrap();
                        assert_eq!(u64::from(rtp.header.sequence_number), received_packets);
                        received_packets += 1;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "raw sink timed out after {received_packets} of {PACKETS} packets"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("raw sink receive failed: {error}"),
                }
            }
        });

        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 16_384).unwrap();
        sender.set_recovery_tuning(without_startup_copy());
        for index in 0..PACKETS {
            sender.send_payload(&payload, ntp, Instant::now()).unwrap();
            if index % PACKETS_PER_BURST == PACKETS_PER_BURST - 1 {
                thread::sleep(Duration::from_millis(4));
            }
        }

        receiver_thread.join().unwrap();
        assert_eq!(sender.pending_send_len(), 0);
        assert_eq!(sender.stats().sent_packets, PACKETS);
    }

    #[test]
    fn main_profile_sustains_needletail_mpegts_while_receiving_concurrently() {
        const PACKETS: u64 = 8_448;
        const PACKETS_PER_BURST: u64 = 8;

        let flow_id = 0x1122_3344;
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut payload = Vec::with_capacity(7 * TS_PACKET_SIZE);
        for pid in 0x0100..0x0107 {
            payload.extend_from_slice(&ts_packet(pid, b"needletail-sustained"));
        }
        assert_eq!(payload.len(), 1_316);

        let mut receiver =
            MainMioReceiver::bind(loopback_any(), flow_id, "needletail", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let expected_payload = payload.clone();
        let receiver_thread = thread::spawn(move || {
            let mut receive = vec![0u8; 65_536];
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut last_rtcp = Instant::now();
            let mut received_packets = 0;

            while received_packets < PACKETS {
                let mut drained = 0;
                while drained < 128 {
                    match receiver.try_recv_payload(&mut receive).unwrap() {
                        Some((_from, received)) => {
                            assert_eq!(received.sequence as u64, received_packets);
                            assert_eq!(received.payload, expected_payload);
                            received_packets += 1;
                            drained += 1;
                        }
                        None => break,
                    }
                }

                let now = Instant::now();
                if now.duration_since(last_rtcp) >= Duration::from_millis(20) {
                    receiver.poll_rtcp_and_send(now, ntp_now()).unwrap();
                    last_rtcp = now;
                }
                assert!(
                    now < deadline,
                    "timed out after receiving {received_packets} of {PACKETS} sustained packets; stats={:?}",
                    receiver.stats()
                );
                if drained == 0 {
                    thread::sleep(Duration::from_millis(1));
                } else if drained == 128 {
                    thread::yield_now();
                }
            }

            receiver.stats()
        });

        let mut sender =
            MainMioSender::connect(loopback_any(), receiver_addr, flow_id, 16_384).unwrap();
        sender.set_recovery_tuning(without_startup_copy());
        let mut feedback = vec![0u8; 65_536];
        for index in 0..PACKETS {
            sender.send_payload(&payload, ntp, Instant::now()).unwrap();
            if index % PACKETS_PER_BURST == PACKETS_PER_BURST - 1 {
                while sender
                    .try_recv_feedback_and_retransmit(&mut feedback)
                    .unwrap()
                    .is_some()
                {}
                thread::sleep(Duration::from_millis(4));
            }
        }

        let sender_stats = sender.stats();
        let receiver_stats = receiver_thread.join().unwrap();
        assert_eq!(sender.pending_send_len(), 0);
        assert_eq!(sender_stats.sent_packets, PACKETS);
        assert_eq!(sender_stats.retransmitted_packets, 0);
        assert_eq!(receiver_stats.received_packets, PACKETS);
        assert_eq!(receiver_stats.total_missing_packets, 0);
        assert_eq!(receiver_stats.currently_missing_packets, 0);
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
        sender.add_peer(rx_a.local_addr().unwrap(), 0).unwrap();
        sender.add_peer(rx_b.local_addr().unwrap(), 0).unwrap();

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
        sender.add_peer(receiver_addr, 0).unwrap();
        sender.add_peer(receiver_addr, 0).unwrap();

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
        sender.add_peer(rx_a.local_addr().unwrap(), 2).unwrap();
        sender.add_peer(rx_b.local_addr().unwrap(), 1).unwrap();

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
        let peer_a = sender.add_peer(rx_a.local_addr().unwrap(), 0).unwrap();
        let peer_b = sender.add_peer(rx_b.local_addr().unwrap(), 0).unwrap();
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
        let _srp_test = lock_srp_test();
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
        let peer_a = sender
            .add_peer(receiver_a.local_addr().unwrap(), 0)
            .unwrap();
        let peer_b = sender
            .add_peer(receiver_b.local_addr().unwrap(), 0)
            .unwrap();
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
        let _srp_test = lock_srp_test();
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
        let _srp_test = lock_srp_test();
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
        let _srp_test = lock_srp_test();
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
        let _srp_test = lock_srp_test();
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
        let _srp_test = lock_srp_test();
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
        sender.set_recovery_tuning(without_startup_copy());

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

    /// Tuning without the startup copy of the first packet (nor B3
    /// duplicates): for tests that count packets on a clean path.
    fn without_startup_copy() -> RecoveryTuning {
        RecoveryTuning {
            duplicate_late_repairs: false,
            ..RecoveryTuning::default()
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
        let deadline = Instant::now() + SRP_HANDSHAKE_TIMEOUT;
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
        let deadline = Instant::now() + SRP_HANDSHAKE_TIMEOUT;
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
