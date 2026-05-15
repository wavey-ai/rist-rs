#![forbid(unsafe_code)]
//! Mio transport boundary for the pure Rust RIST implementation.
//!
//! This is intentionally small. The protocol state lives in `rist-core`; this
//! crate only owns nonblocking UDP readiness and datagram movement.

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};
use rist_core::auth::{EapSrpAuthenticatorSession, EapSrpClientSession, EapolFrame};
use rist_core::crypto::PskKey;
use rist_core::packet::gre::{
    BufferNegotiation, GreHeader, GreKeepalive, OwnedBufferNegotiationPacket, OwnedKeepalivePacket,
    GRE_PROTOCOL_TYPE_EAPOL, GRE_PROTOCOL_TYPE_KEEPALIVE, VSF_SUBTYPE_BUFFER_NEGOTIATION,
    VSF_SUBTYPE_KEEPALIVE,
};
use rist_core::packet::rtp::{encode_packet, RtpHeader, RtpPacket};
use rist_core::time::ntp_now;
use rist_core::{
    packet::rtcp::NackMode, Error as CoreError, MainControlPacket, MainOutboundPacket,
    MainReceiverCore, MainReceiverFeedback, MainSenderCore, OutboundPacket, ReceivedPayload,
    ReceiverStats, SenderStats, SimpleReceiverCore, SimpleSenderCore, SrpCredentialStore,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

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
            Some(_) => self.socket.send(packet),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no remote peer configured",
            )),
        }
    }

    pub fn send_packet_to(&mut self, peer: SocketAddr, packet: &[u8]) -> io::Result<usize> {
        self.socket.send_to(packet, peer)
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
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
        self.socket.send_to(&packet, peer)
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

pub struct SimpleMioSender {
    socket: RtpUdpSocket,
    core: SimpleSenderCore,
}

impl SimpleMioSender {
    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        ssrc: u32,
        history_packets: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::connect(local, peer, ssrc)?,
            core: SimpleSenderCore::new(ssrc, history_packets),
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

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn send_outbound(&mut self, packet: &OutboundPacket) -> io::Result<usize> {
        self.socket.send_packet(&packet.bytes)
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<OutboundPacket> {
        let packet = self.build_payload(payload, ntp_timestamp, now);
        self.send_outbound(&packet)?;
        Ok(packet)
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.socket.set_multicast_loop_v4(on)
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_multicast_ttl_v4(ttl)
    }

    pub fn send_rtcp(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.socket.send_packet(packet)
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
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.send_rtcp(&packet).map(Some)
    }

    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let Some((_from, feedback)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        self.handle_feedback_and_retransmit(feedback)
    }

    pub fn try_recv_feedback_and_retransmit_at(
        &mut self,
        buf: &mut [u8],
        now_ntp: u64,
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let Some((_from, feedback)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        self.handle_feedback_and_retransmit_at(feedback, now_ntp)
            .map(Some)
    }

    fn handle_feedback_and_retransmit(
        &mut self,
        feedback: &[u8],
    ) -> io::Result<Option<Vec<OutboundPacket>>> {
        let retries = self
            .core
            .handle_feedback(feedback)
            .map_err(core_to_io_error)?;
        for retry in &retries {
            self.socket.send_packet(&retry.bytes)?;
        }
        Ok(Some(retries))
    }

    fn handle_feedback_and_retransmit_at(
        &mut self,
        feedback: &[u8],
        now_ntp: u64,
    ) -> io::Result<Vec<OutboundPacket>> {
        let retries = self
            .core
            .handle_feedback_at(feedback, now_ntp)
            .map_err(core_to_io_error)?;
        for retry in &retries {
            self.socket.send_packet(&retry.bytes)?;
        }
        Ok(retries)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.leave_multicast_v4(multiaddr, interface)
    }
}

pub struct SimpleMioReceiver {
    socket: RtpUdpSocket,
    core: SimpleReceiverCore,
    last_peer: Option<SocketAddr>,
}

impl SimpleMioReceiver {
    pub fn bind(
        local: SocketAddr,
        flow_id: u32,
        cname: impl Into<String>,
        nack_mode: NackMode,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::bind(local, flow_id)?,
            core: SimpleReceiverCore::new(flow_id, cname, nack_mode),
            last_peer: None,
        })
    }

    pub fn try_recv_payload(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, ReceivedPayload)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        let payload = self.core.accept_packet(packet).map_err(core_to_io_error)?;
        self.last_peer = Some(from);
        Ok(Some((from, payload)))
    }

    pub fn feedback_packet(&mut self) -> Vec<u8> {
        self.core.build_feedback_and_record()
    }

    pub fn poll_rtcp_packet(&mut self, now: Instant, now_ntp: u64) -> Option<Vec<u8>> {
        self.core.poll_rtcp(now, now_ntp)
    }

    pub fn poll_rtcp_and_send(&mut self, now: Instant, now_ntp: u64) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_peer else {
            return Ok(None);
        };
        let Some(packet) = self.poll_rtcp_packet(now, now_ntp) else {
            return Ok(None);
        };
        self.socket.send_packet_to(peer, &packet).map(Some)
    }

    pub fn send_feedback(&mut self) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_peer else {
            return Ok(None);
        };
        self.send_feedback_to(peer).map(Some)
    }

    pub fn send_feedback_to(&mut self, peer: SocketAddr) -> io::Result<usize> {
        let feedback = self.feedback_packet();
        self.socket.send_packet_to(peer, &feedback)
    }

    pub fn try_recv_rtcp_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        let responses = self.core.handle_rtcp(packet).map_err(core_to_io_error)?;
        for response in &responses {
            self.socket.send_packet_to(from, response)?;
        }
        self.last_peer = Some(from);
        Ok(Some(responses.len()))
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.core.missing_sequences()
    }

    pub fn stats(&self) -> ReceiverStats {
        self.core.stats()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.join_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.socket.leave_multicast_v4(multiaddr, interface)
    }
}

pub struct MainMioSender {
    socket: RtpUdpSocket,
    core: MainSenderCore,
    srp: Option<EapSrpClientSession>,
}

impl MainMioSender {
    pub fn connect(
        local: SocketAddr,
        peer: SocketAddr,
        flow_id: u32,
        history_packets: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: RtpUdpSocket::connect(local, peer, flow_id)?,
            core: MainSenderCore::new(flow_id, history_packets),
            srp: None,
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

    pub fn set_ports(&mut self, virt_src_port: u16, virt_dst_port: u16) {
        self.core.set_ports(virt_src_port, virt_dst_port);
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
    }

    pub fn set_srp_client_session(&mut self, session: EapSrpClientSession) {
        self.srp = Some(session);
    }

    pub fn srp_authenticated(&self) -> bool {
        self.srp
            .as_ref()
            .map(|session| session.authenticated())
            .unwrap_or(true)
    }

    pub fn stats(&self) -> SenderStats {
        self.core.stats()
    }

    pub fn send_outbound(&mut self, packet: &MainOutboundPacket) -> io::Result<usize> {
        self.ensure_srp_authenticated()?;
        self.socket.send_packet(&packet.bytes)
    }

    pub fn send_payload(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> io::Result<MainOutboundPacket> {
        self.ensure_srp_authenticated()?;
        let packet = self.build_payload(payload, ntp_timestamp, now);
        self.send_outbound(&packet)?;
        Ok(packet)
    }

    pub fn poll_rtcp_and_send(
        &mut self,
        now: Instant,
        ntp_timestamp: u64,
    ) -> io::Result<Option<MainControlPacket>> {
        self.ensure_srp_authenticated()?;
        let Some(packet) = self.core.poll_rtcp(now, ntp_timestamp) else {
            return Ok(None);
        };
        self.socket.send_packet(&packet.bytes)?;
        Ok(Some(packet))
    }

    pub fn build_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> MainControlPacket {
        self.core.build_keepalive(keepalive)
    }

    pub fn send_keepalive(&mut self, keepalive: GreKeepalive<'_>) -> io::Result<MainControlPacket> {
        let packet = self.build_keepalive(keepalive);
        self.socket.send_packet(&packet.bytes)?;
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
        let packet = self.build_buffer_negotiation(negotiation);
        self.socket.send_packet(&packet.bytes)?;
        Ok(packet)
    }

    pub fn start_srp_authentication(&mut self) -> io::Result<MainControlPacket> {
        let Some(session) = &self.srp else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SRP client session is not configured",
            ));
        };
        self.send_eapol_frame(&session.start())
    }

    pub fn send_eapol_frame(&mut self, frame: &EapolFrame) -> io::Result<MainControlPacket> {
        let packet = self.core.build_eapol(frame).map_err(core_to_io_error)?;
        self.socket.send_packet(&packet.bytes)?;
        Ok(packet)
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<EapolFrame>> {
        let Some((_from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if !is_eapol_datagram(packet) {
            return Ok(None);
        }
        self.handle_eapol_datagram(packet)
    }

    pub fn try_recv_keepalive(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedKeepalivePacket)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let keepalive = self
            .core
            .accept_keepalive(packet)
            .map_err(core_to_io_error)?;
        Ok(Some((from, keepalive)))
    }

    pub fn try_recv_buffer_negotiation(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedBufferNegotiationPacket)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let negotiation = self
            .core
            .accept_buffer_negotiation(packet)
            .map_err(core_to_io_error)?;
        Ok(Some((from, negotiation)))
    }

    pub fn try_recv_feedback_and_retransmit(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<Vec<MainOutboundPacket>>> {
        let Some((_from, feedback)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(feedback) {
            self.handle_eapol_datagram(feedback)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let retries = match self.core.handle_feedback(feedback) {
            Ok(retries) => retries,
            Err(err) if is_main_control_decode_error(&err) => return Ok(None),
            Err(err) => return Err(core_to_io_error(err)),
        };
        for retry in &retries {
            self.socket.send_packet(&retry.bytes)?;
        }
        Ok(Some(retries))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn handle_eapol_datagram(&mut self, packet: &[u8]) -> io::Result<Option<EapolFrame>> {
        let frame = self.core.accept_eapol(packet).map_err(core_to_io_error)?;
        let authenticated = self.srp_authenticated();
        let response = match &mut self.srp {
            Some(session) => match session.handle_frame(&frame) {
                Ok(response) => response,
                Err(rist_core::Error::InvalidEapPacket) if authenticated => None,
                Err(err) => return Err(core_to_io_error(err)),
            },
            None => None,
        };
        if let Some(response) = response {
            self.send_eapol_frame(&response)?;
        }
        Ok(Some(frame))
    }

    fn ensure_srp_authenticated(&self) -> io::Result<()> {
        if self.srp_authenticated() {
            Ok(())
        } else {
            Err(srp_not_authenticated_error())
        }
    }
}

pub struct MainMioReceiver {
    socket: RtpUdpSocket,
    core: MainReceiverCore,
    last_peer: Option<SocketAddr>,
    srp: Option<EapSrpAuthenticatorSession>,
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
            last_peer: None,
            srp: None,
        })
    }

    pub fn try_recv_payload(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, ReceivedPayload)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(from, packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let payload = match self.core.accept_packet(packet) {
            Ok(payload) => payload,
            Err(CoreError::UnsupportedRtpPayloadType(_)) => {
                let responses = self
                    .core
                    .handle_rtcp(packet, ntp_now())
                    .map_err(core_to_io_error)?;
                for response in &responses {
                    self.socket.send_packet_to(from, &response.bytes)?;
                }
                self.last_peer = Some(from);
                return Ok(None);
            }
            Err(err) if is_main_control_decode_error(&err) => {
                self.last_peer = Some(from);
                return Ok(None);
            }
            Err(err) => return Err(core_to_io_error(err)),
        };
        self.last_peer = Some(from);
        Ok(Some((from, payload)))
    }

    pub fn set_tx_key(&mut self, key: PskKey) {
        self.core.set_tx_key(key);
    }

    pub fn set_rx_key(&mut self, key: PskKey) {
        self.core.set_rx_key(key);
    }

    pub fn enable_srp_authenticator(&mut self, store: SrpCredentialStore) {
        self.srp = Some(EapSrpAuthenticatorSession::new(store).with_session_key_passphrase(false));
    }

    pub fn set_srp_authenticator_session(&mut self, session: EapSrpAuthenticatorSession) {
        self.srp = Some(session);
    }

    pub fn srp_authenticated(&self) -> bool {
        self.srp
            .as_ref()
            .map(|session| session.authenticated())
            .unwrap_or(true)
    }

    pub fn send_feedback(&mut self) -> io::Result<Option<usize>> {
        let Some(peer) = self.last_peer else {
            return Ok(None);
        };
        self.send_feedback_to(peer).map(Some)
    }

    pub fn send_feedback_to(&mut self, peer: SocketAddr) -> io::Result<usize> {
        self.ensure_srp_authenticated()?;
        let feedback = self.core.build_feedback();
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
        self.ensure_srp_authenticated()?;
        let Some(packet) = self.core.poll_rtcp(now, now_ntp) else {
            return Ok(None);
        };
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(Some(packet))
    }

    pub fn try_recv_rtcp_and_respond(
        &mut self,
        buf: &mut [u8],
        now_ntp: u64,
    ) -> io::Result<Option<usize>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(from, packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let responses = match self.core.handle_rtcp(packet, now_ntp) {
            Ok(responses) => responses,
            Err(err) if is_main_control_decode_error(&err) => {
                self.last_peer = Some(from);
                return Ok(None);
            }
            Err(err) => return Err(core_to_io_error(err)),
        };
        for response in &responses {
            self.socket.send_packet_to(from, &response.bytes)?;
        }
        self.last_peer = Some(from);
        Ok(Some(responses.len()))
    }

    pub fn send_keepalive_to(
        &mut self,
        peer: SocketAddr,
        keepalive: GreKeepalive<'_>,
    ) -> io::Result<MainControlPacket> {
        let packet = self.core.build_keepalive(keepalive);
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn send_buffer_negotiation_to(
        &mut self,
        peer: SocketAddr,
        negotiation: BufferNegotiation<'_>,
    ) -> io::Result<MainControlPacket> {
        let packet = self.core.build_buffer_negotiation(negotiation);
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn send_eapol_frame_to(
        &mut self,
        peer: SocketAddr,
        frame: &EapolFrame,
    ) -> io::Result<MainControlPacket> {
        let packet = self.core.build_eapol(frame).map_err(core_to_io_error)?;
        self.socket.send_packet_to(peer, &packet.bytes)?;
        Ok(packet)
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> io::Result<Option<EapolFrame>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if !is_eapol_datagram(packet) {
            return Ok(None);
        }
        self.handle_eapol_datagram(from, packet)
    }

    pub fn try_recv_keepalive(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedKeepalivePacket)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(from, packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let keepalive = self
            .core
            .accept_keepalive(packet)
            .map_err(core_to_io_error)?;
        self.last_peer = Some(from);
        Ok(Some((from, keepalive)))
    }

    pub fn try_recv_buffer_negotiation(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(SocketAddr, OwnedBufferNegotiationPacket)>> {
        let Some((from, packet)) = self.socket.recv_datagram(buf)? else {
            return Ok(None);
        };
        if is_eapol_datagram(packet) {
            self.handle_eapol_datagram(from, packet)?;
            return Ok(None);
        }
        if !self.srp_authenticated() {
            return Ok(None);
        }
        let negotiation = self
            .core
            .accept_buffer_negotiation(packet)
            .map_err(core_to_io_error)?;
        self.last_peer = Some(from);
        Ok(Some((from, negotiation)))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        self.core.missing_sequences()
    }

    pub fn stats(&self) -> ReceiverStats {
        self.core.stats()
    }

    fn handle_eapol_datagram(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
    ) -> io::Result<Option<EapolFrame>> {
        let frame = self.core.accept_eapol(packet).map_err(core_to_io_error)?;
        let authenticated = self.srp_authenticated();
        let response = match &mut self.srp {
            Some(session) => match session.handle_frame(&frame) {
                Ok(response) => response,
                Err(rist_core::Error::InvalidEapPacket) if authenticated => None,
                Err(err) => return Err(core_to_io_error(err)),
            },
            None => None,
        };
        if let Some(response) = response {
            self.send_eapol_frame_to(from, &response)?;
        }
        self.last_peer = Some(from);
        Ok(Some(frame))
    }

    fn ensure_srp_authenticated(&self) -> io::Result<()> {
        if self.srp_authenticated() {
            Ok(())
        } else {
            Err(srp_not_authenticated_error())
        }
    }
}

fn core_to_io_error(err: rist_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn is_eapol_datagram(packet: &[u8]) -> bool {
    GreHeader::decode(packet)
        .map(|(gre, _)| gre.protocol_type == GRE_PROTOCOL_TYPE_EAPOL)
        .unwrap_or(false)
}

fn srp_not_authenticated_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "SRP authentication has not completed",
    )
}

fn is_main_control_decode_error(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::UnsupportedGreProtocol(GRE_PROTOCOL_TYPE_KEEPALIVE)
            | CoreError::UnsupportedVsfSubtype(VSF_SUBTYPE_KEEPALIVE)
            | CoreError::UnsupportedVsfSubtype(VSF_SUBTYPE_BUFFER_NEGOTIATION)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_core::mpegts::{TS_NULL_PID, TS_PACKET_SIZE, TS_SYNC_BYTE};
    use rist_core::time::ntp_from_unix_duration;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
    use std::thread;
    use std::time::Duration;

    fn loopback_any() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
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
    fn simple_profile_recovers_dropped_udp_payload() {
        let flow_id = 0x1122_3344;
        let now = Instant::now();
        let ntp = ntp_from_unix_duration(Duration::from_secs(1));
        let mut receiver =
            SimpleMioReceiver::bind(loopback_any(), flow_id, "rust", NackMode::Range).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender =
            SimpleMioSender::connect(loopback_any(), receiver_addr, flow_id, 64).unwrap();
        let sender_addr = sender.local_addr().unwrap();

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
        let port_probe =
            StdUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                .unwrap();
        let port = port_probe.local_addr().unwrap().port();
        drop(port_probe);

        let group = Ipv4Addr::new(239, 255, (port >> 8) as u8, port as u8);
        let interface = Ipv4Addr::UNSPECIFIED;
        let receiver_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(group, port));

        let mut receiver =
            SimpleMioReceiver::bind(receiver_addr, flow_id, "rust", NackMode::Range).unwrap();
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
