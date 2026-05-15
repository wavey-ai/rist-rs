//! Pure Rust RIST implementation surface.
//!
//! This module is available with the `pure-rust` feature. It exposes the
//! sans-I/O protocol core and the Mio UDP transport without going through
//! librist FFI.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Instant;
use thiserror::Error;

pub mod core {
    pub use rist_core::*;
}

pub mod mio {
    pub use rist_mio::{
        MainMioMultiSend, MainMioMultiSender, MainMioPeer, MainMioReceiver, MainMioSender,
        MainMioSessionPoll, RtpUdpSocket, SimpleMioReceiver, SimpleMioSender,
    };
}

pub use rist_core::{
    AesKeySize, CongestionControlMode, ConnectionConfig, EncryptionConfig, Endpoint,
    MainControlPacket, MainOutboundPacket, MainReceiverCore, MainReceiverFeedback, MainSenderCore,
    MainSessionConfig, MainSessionPoll, MultiplexMode, NullPacketSuppression, OutboundPacket,
    PeerConfig, PeerSelection, Profile, PskKey, ReceivedPayload, ReceiverStats, RecoveryConfig,
    RecoveryMode, RtcpIntervals, SenderStats, SimpleReceiverCore, SimpleSenderCore,
    SrpCredentialStore, SrpUserRecord, TimingMode, VirtualPorts, WeightedPeerSelector,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Core(#[from] rist_core::Error),

    #[error("profile {0:?} is not implemented by the pure Rust transport")]
    UnsupportedProfile(Profile),

    #[error("sender peer address is missing")]
    MissingPeer,

    #[error("URL must be a sender peer URL")]
    ExpectedPeerUrl,

    #[error("URL must be a receiver listen URL")]
    ExpectedListenUrl,

    #[error("address did not resolve: {0}")]
    AddressResolution(String),
}

#[derive(Debug, Clone)]
struct PskOptions {
    key_size_bits: u32,
    key_rotation: Option<u64>,
    password: Vec<u8>,
}

impl PskOptions {
    fn from_config(config: &EncryptionConfig) -> Self {
        Self {
            key_size_bits: u32::from(config.key_size_bits),
            key_rotation: config.key_rotation.map(u64::from),
            password: config.secret.as_bytes().to_vec(),
        }
    }

    fn tx_key(&self) -> Result<PskKey> {
        match self.key_rotation {
            Some(rotation) => Ok(PskKey::with_key_rotation(
                self.key_size_bits,
                rotation,
                &self.password,
            )?),
            None => Ok(PskKey::new(self.key_size_bits, &self.password)?),
        }
    }

    fn rx_key(&self) -> Result<PskKey> {
        Ok(PskKey::receiver(self.key_size_bits, &self.password)?)
    }
}

#[derive(Debug, Clone)]
pub struct SenderBuilder {
    profile: Profile,
    local: SocketAddr,
    peer: Option<SocketAddr>,
    flow_id: u32,
    history_packets: usize,
    virtual_ports: VirtualPorts,
    session_config: MainSessionConfig,
    multicast_interface_v4: Option<Ipv4Addr>,
    initial_rtp_sequence: Option<u32>,
    null_packet_suppression: bool,
    psk: Option<PskOptions>,
    srp_client: Option<(String, Vec<u8>)>,
}

impl SenderBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            peer: None,
            flow_id: 0x1122_3344,
            history_packets: 1024,
            virtual_ports: VirtualPorts::default(),
            session_config: MainSessionConfig::default(),
            multicast_interface_v4: None,
            initial_rtp_sequence: None,
            null_packet_suppression: false,
            psk: None,
            srp_client: None,
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self
    }

    pub fn peer_addr(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    pub fn peer_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if config.endpoint.listen {
            return Err(Error::ExpectedPeerUrl);
        }
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            self.srp_client = Some((username.clone(), password.as_bytes().to_vec()));
        }
        self.multicast_interface_v4 = parse_miface_v4(config.endpoint.miface.as_deref())?;
        self.initial_rtp_sequence = parse_nonnegative_i32(config.advanced.rtp_sequence);
        self.virtual_ports = config.virtual_ports;
        self.session_config = config.connection.into();
        self.peer = Some(resolve_endpoint(&config.endpoint)?);
        Ok(self)
    }

    pub fn flow_id(mut self, flow_id: u32) -> Self {
        self.flow_id = flow_id;
        self
    }

    pub fn history_packets(mut self, history_packets: usize) -> Self {
        self.history_packets = history_packets;
        self
    }

    pub fn virtual_ports(mut self, src: u16, dst: u16) -> Self {
        self.virtual_ports = VirtualPorts { src, dst };
        self
    }

    pub fn session_config(mut self, config: MainSessionConfig) -> Self {
        self.session_config = config;
        self
    }

    pub fn multicast_interface_v4(mut self, interface: Ipv4Addr) -> Self {
        self.multicast_interface_v4 = Some(interface);
        self
    }

    pub fn initial_rtp_sequence(mut self, sequence: u32) -> Self {
        self.initial_rtp_sequence = Some(sequence);
        self
    }

    pub fn null_packet_suppression(mut self, enabled: bool) -> Self {
        self.null_packet_suppression = enabled;
        self
    }

    pub fn psk(mut self, key_size_bits: u32, password: impl AsRef<[u8]>) -> Self {
        self.psk = Some(PskOptions {
            key_size_bits,
            key_rotation: None,
            password: password.as_ref().to_vec(),
        });
        self
    }

    pub fn psk_with_rotation(
        mut self,
        key_size_bits: u32,
        key_rotation: u64,
        password: impl AsRef<[u8]>,
    ) -> Self {
        self.psk = Some(PskOptions {
            key_size_bits,
            key_rotation: Some(key_rotation),
            password: password.as_ref().to_vec(),
        });
        self
    }

    pub fn srp_client(mut self, username: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        self.srp_client = Some((username.into(), password.as_ref().to_vec()));
        self
    }

    pub fn connect(self) -> Result<Sender> {
        let peer = self.peer.ok_or(Error::MissingPeer)?;
        match self.profile {
            Profile::Simple => {
                let mut sender = rist_mio::SimpleMioSender::connect(
                    self.local,
                    peer,
                    self.flow_id,
                    self.history_packets,
                )?;
                if let Some(interface) = self.multicast_interface_v4 {
                    sender.set_multicast_if_v4(interface)?;
                }
                if let Some(sequence) = self.initial_rtp_sequence {
                    sender.set_next_sequence(sequence);
                }
                if self.null_packet_suppression {
                    sender.enable_null_packet_suppression();
                }
                Ok(Sender::Simple(sender))
            }
            Profile::Main | Profile::Advanced => {
                let mut sender = rist_mio::MainMioSender::connect(
                    self.local,
                    peer,
                    self.flow_id,
                    self.history_packets,
                )?;
                sender.set_ports(self.virtual_ports.src, self.virtual_ports.dst);
                sender.set_session_config(self.session_config);
                if let Some(interface) = self.multicast_interface_v4 {
                    sender.set_multicast_if_v4(interface)?;
                }
                if let Some(sequence) = self.initial_rtp_sequence {
                    sender.set_next_rtp_sequence(sequence);
                }
                if self.null_packet_suppression {
                    sender.enable_null_packet_suppression();
                }
                if let Some(psk) = self.psk {
                    sender.set_tx_key(psk.tx_key()?);
                    sender.set_rx_key(psk.rx_key()?);
                }
                if let Some((username, password)) = self.srp_client {
                    sender.enable_srp_client(username, password);
                }
                Ok(Sender::Main(sender))
            }
        }
    }
}

pub enum Sender {
    Simple(rist_mio::SimpleMioSender),
    Main(rist_mio::MainMioSender),
}

impl Sender {
    pub fn builder(profile: Profile) -> SenderBuilder {
        SenderBuilder::new(profile)
    }

    pub fn connect(profile: Profile, local: SocketAddr, peer: SocketAddr) -> Result<Self> {
        Self::builder(profile)
            .local_addr(local)
            .peer_addr(peer)
            .connect()
    }

    pub fn connect_url(profile: Profile, url: &str) -> Result<Self> {
        Self::builder(profile).peer_url(url)?.connect()
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<usize> {
        self.send_at(payload, rist_core::time::ntp_now(), Instant::now())
    }

    pub fn send_at(&mut self, payload: &[u8], ntp_timestamp: u64, now: Instant) -> Result<usize> {
        match self {
            Self::Simple(sender) => {
                sender.send_payload(payload, ntp_timestamp, now)?;
            }
            Self::Main(sender) => {
                sender.send_payload(payload, ntp_timestamp, now)?;
            }
        }
        Ok(payload.len())
    }

    pub fn poll_rtcp(&mut self) -> Result<Option<usize>> {
        let now = Instant::now();
        let ntp = rist_core::time::ntp_now();
        match self {
            Self::Simple(sender) => Ok(sender.poll_rtcp_and_send(now, ntp)?),
            Self::Main(sender) => Ok(sender
                .poll_rtcp_and_send(now, ntp)?
                .map(|packet| packet.bytes.len())),
        }
    }

    pub fn poll_session(&mut self) -> Result<MainSessionPoll> {
        match self {
            Self::Main(sender) => Ok(sender.poll_session(Instant::now())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn poll_keepalive(&mut self, mac: [u8; 6]) -> Result<Option<usize>> {
        match self {
            Self::Main(sender) => Ok(sender
                .poll_session_and_send_keepalive(
                    Instant::now(),
                    rist_core::packet::gre::GreKeepalive::librist_default(mac),
                )?
                .keepalive
                .map(|packet| packet.bytes.len())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn start_srp_authentication(&mut self) -> Result<Option<usize>> {
        match self {
            Self::Main(sender) => Ok(Some(sender.start_srp_authentication()?.bytes.len())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> Result<Option<()>> {
        match self {
            Self::Main(sender) => Ok(sender.try_recv_eapol_and_respond(buf)?.map(|_| ())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn srp_authenticated(&self) -> bool {
        match self {
            Self::Main(sender) => sender.srp_authenticated(),
            Self::Simple(_) => true,
        }
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> Result<()> {
        match self {
            Self::Main(sender) => Ok(sender.update_srp_client_password(password)?),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn try_recv_feedback_and_retransmit(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self {
            Self::Simple(sender) => Ok(sender
                .try_recv_feedback_and_retransmit(buf)?
                .map(|packets| packets.len())),
            Self::Main(sender) => Ok(sender
                .try_recv_feedback_and_retransmit(buf)?
                .map(|packets| packets.len())),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(match self {
            Self::Simple(sender) => sender.local_addr()?,
            Self::Main(sender) => sender.local_addr()?,
        })
    }

    pub fn stats(&self) -> SenderStats {
        match self {
            Self::Simple(sender) => sender.stats(),
            Self::Main(sender) => sender.stats(),
        }
    }
}

#[derive(Debug, Clone)]
struct MultiSenderPeer {
    addr: SocketAddr,
    weight: u32,
}

#[derive(Debug, Clone)]
pub struct MultiSenderBuilder {
    profile: Profile,
    local: SocketAddr,
    peers: Vec<MultiSenderPeer>,
    flow_id: u32,
    history_packets: usize,
    virtual_ports: VirtualPorts,
    session_config: MainSessionConfig,
    multicast_interface_v4: Option<Ipv4Addr>,
    initial_rtp_sequence: Option<u32>,
    null_packet_suppression: bool,
    psk: Option<PskOptions>,
}

impl MultiSenderBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            peers: Vec::new(),
            flow_id: 0x1122_3344,
            history_packets: 1024,
            virtual_ports: VirtualPorts::default(),
            session_config: MainSessionConfig::default(),
            multicast_interface_v4: None,
            initial_rtp_sequence: None,
            null_packet_suppression: false,
            psk: None,
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self
    }

    pub fn peer_addr(mut self, peer: SocketAddr, weight: u32) -> Self {
        self.peers.push(MultiSenderPeer { addr: peer, weight });
        self
    }

    pub fn peer_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if config.endpoint.listen {
            return Err(Error::ExpectedPeerUrl);
        }
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        self.multicast_interface_v4 = parse_miface_v4(config.endpoint.miface.as_deref())?;
        self.initial_rtp_sequence = parse_nonnegative_i32(config.advanced.rtp_sequence);
        self.virtual_ports = config.virtual_ports;
        self.session_config = config.connection.into();
        self.peers.push(MultiSenderPeer {
            addr: resolve_endpoint(&config.endpoint)?,
            weight: config.advanced.weight,
        });
        Ok(self)
    }

    pub fn flow_id(mut self, flow_id: u32) -> Self {
        self.flow_id = flow_id;
        self
    }

    pub fn history_packets(mut self, history_packets: usize) -> Self {
        self.history_packets = history_packets;
        self
    }

    pub fn virtual_ports(mut self, src: u16, dst: u16) -> Self {
        self.virtual_ports = VirtualPorts { src, dst };
        self
    }

    pub fn session_config(mut self, config: MainSessionConfig) -> Self {
        self.session_config = config;
        self
    }

    pub fn multicast_interface_v4(mut self, interface: Ipv4Addr) -> Self {
        self.multicast_interface_v4 = Some(interface);
        self
    }

    pub fn initial_rtp_sequence(mut self, sequence: u32) -> Self {
        self.initial_rtp_sequence = Some(sequence);
        self
    }

    pub fn null_packet_suppression(mut self, enabled: bool) -> Self {
        self.null_packet_suppression = enabled;
        self
    }

    pub fn psk(mut self, key_size_bits: u32, password: impl AsRef<[u8]>) -> Self {
        self.psk = Some(PskOptions {
            key_size_bits,
            key_rotation: None,
            password: password.as_ref().to_vec(),
        });
        self
    }

    pub fn connect(self) -> Result<MultiSender> {
        if self.peers.is_empty() {
            return Err(Error::MissingPeer);
        }
        match self.profile {
            Profile::Main | Profile::Advanced => {
                let mut sender = rist_mio::MainMioMultiSender::bind(
                    self.local,
                    self.flow_id,
                    self.history_packets,
                )?;
                sender.set_ports(self.virtual_ports.src, self.virtual_ports.dst);
                sender.set_session_config(self.session_config);
                if let Some(interface) = self.multicast_interface_v4 {
                    sender.set_multicast_if_v4(interface)?;
                }
                if let Some(sequence) = self.initial_rtp_sequence {
                    sender.set_next_rtp_sequence(sequence);
                }
                if self.null_packet_suppression {
                    sender.enable_null_packet_suppression();
                }
                if let Some(psk) = self.psk {
                    sender.set_tx_key(psk.tx_key()?);
                    sender.set_rx_key(psk.rx_key()?);
                }
                for peer in self.peers {
                    sender.add_peer(peer.addr, peer.weight);
                }
                Ok(MultiSender::Main(sender))
            }
            Profile::Simple => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }
}

pub enum MultiSender {
    Main(rist_mio::MainMioMultiSender),
}

impl MultiSender {
    pub fn builder(profile: Profile) -> MultiSenderBuilder {
        MultiSenderBuilder::new(profile)
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<usize>> {
        self.send_at(payload, rist_core::time::ntp_now(), Instant::now())
    }

    pub fn send_at(
        &mut self,
        payload: &[u8],
        ntp_timestamp: u64,
        now: Instant,
    ) -> Result<Vec<usize>> {
        match self {
            Self::Main(sender) => Ok(sender.send_payload(payload, ntp_timestamp, now)?.peers),
        }
    }

    pub fn poll_keepalive(&mut self, mac: [u8; 6]) -> Result<Option<usize>> {
        match self {
            Self::Main(sender) => Ok(sender
                .poll_session_and_send_keepalive(
                    Instant::now(),
                    rist_core::packet::gre::GreKeepalive::librist_default(mac),
                )?
                .keepalive
                .map(|packet| packet.bytes.len())),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        match self {
            Self::Main(sender) => Ok(sender.local_addr()?),
        }
    }

    pub fn stats(&self) -> SenderStats {
        match self {
            Self::Main(sender) => sender.stats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverBuilder {
    profile: Profile,
    local: SocketAddr,
    flow_id: u32,
    cname: String,
    nack_mode: rist_core::packet::rtcp::NackMode,
    session_config: MainSessionConfig,
    psk: Option<PskOptions>,
    srp_store: Option<SrpCredentialStore>,
}

impl ReceiverBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            flow_id: 0x1122_3344,
            cname: "rust".to_string(),
            nack_mode: rist_core::packet::rtcp::NackMode::Range,
            session_config: MainSessionConfig::default(),
            psk: None,
            srp_store: None,
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self
    }

    pub fn listen_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if !config.endpoint.listen {
            return Err(Error::ExpectedListenUrl);
        }
        if let Some(cname) = config.cname {
            self.cname = cname;
        }
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            let mut store = SrpCredentialStore::new();
            store.stage_password(username, password.as_bytes())?;
            self.srp_store = Some(store);
        }
        self.session_config = config.connection.into();
        self.local = resolve_endpoint(&config.endpoint)?;
        Ok(self)
    }

    pub fn flow_id(mut self, flow_id: u32) -> Self {
        self.flow_id = flow_id;
        self
    }

    pub fn cname(mut self, cname: impl Into<String>) -> Self {
        self.cname = cname.into();
        self
    }

    pub fn nack_mode(mut self, nack_mode: rist_core::packet::rtcp::NackMode) -> Self {
        self.nack_mode = nack_mode;
        self
    }

    pub fn session_config(mut self, config: MainSessionConfig) -> Self {
        self.session_config = config;
        self
    }

    pub fn psk(mut self, key_size_bits: u32, password: impl AsRef<[u8]>) -> Self {
        self.psk = Some(PskOptions {
            key_size_bits,
            key_rotation: None,
            password: password.as_ref().to_vec(),
        });
        self
    }

    pub fn psk_with_rotation(
        mut self,
        key_size_bits: u32,
        key_rotation: u64,
        password: impl AsRef<[u8]>,
    ) -> Self {
        self.psk = Some(PskOptions {
            key_size_bits,
            key_rotation: Some(key_rotation),
            password: password.as_ref().to_vec(),
        });
        self
    }

    pub fn srp_password(
        mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let mut store = self.srp_store.unwrap_or_default();
        store.stage_password(username, password)?;
        self.srp_store = Some(store);
        Ok(self)
    }

    pub fn srp_store(mut self, store: SrpCredentialStore) -> Self {
        self.srp_store = Some(store);
        self
    }

    pub fn bind(self) -> Result<Receiver> {
        match self.profile {
            Profile::Simple => Ok(Receiver::Simple(rist_mio::SimpleMioReceiver::bind(
                self.local,
                self.flow_id,
                self.cname,
                self.nack_mode,
            )?)),
            Profile::Main | Profile::Advanced => {
                let mut receiver = rist_mio::MainMioReceiver::bind(
                    self.local,
                    self.flow_id,
                    self.cname,
                    self.nack_mode,
                )?;
                receiver.set_session_config(self.session_config);
                if let Some(psk) = self.psk {
                    receiver.set_tx_key(psk.tx_key()?);
                    receiver.set_rx_key(psk.rx_key()?);
                }
                if let Some(store) = self.srp_store {
                    receiver.enable_srp_authenticator(store);
                }
                Ok(Receiver::Main(receiver))
            }
        }
    }
}

pub enum Receiver {
    Simple(rist_mio::SimpleMioReceiver),
    Main(rist_mio::MainMioReceiver),
}

impl Receiver {
    pub fn builder(profile: Profile) -> ReceiverBuilder {
        ReceiverBuilder::new(profile)
    }

    pub fn bind(profile: Profile, local: SocketAddr, flow_id: u32) -> Result<Self> {
        Self::builder(profile)
            .local_addr(local)
            .flow_id(flow_id)
            .bind()
    }

    pub fn bind_url(profile: Profile, url: &str) -> Result<Self> {
        Self::builder(profile).listen_url(url)?.bind()
    }

    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(SocketAddr, ReceivedPayload)>> {
        match self {
            Self::Simple(receiver) => Ok(receiver.try_recv_payload(buf)?),
            Self::Main(receiver) => Ok(receiver.try_recv_payload(buf)?),
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Option<ReceivedPayload>> {
        Ok(self.recv_from(buf)?.map(|(_from, payload)| payload))
    }

    pub fn send_feedback(&mut self) -> Result<Option<usize>> {
        match self {
            Self::Simple(receiver) => Ok(receiver.send_feedback()?),
            Self::Main(receiver) => Ok(receiver.send_feedback()?),
        }
    }

    pub fn poll_rtcp(&mut self) -> Result<Option<usize>> {
        let now = Instant::now();
        let ntp = rist_core::time::ntp_now();
        match self {
            Self::Simple(receiver) => Ok(receiver.poll_rtcp_and_send(now, ntp)?),
            Self::Main(receiver) => Ok(receiver
                .poll_rtcp_and_send(now, ntp)?
                .map(|packet| packet.bytes.len())),
        }
    }

    pub fn poll_session(&mut self) -> Result<MainSessionPoll> {
        match self {
            Self::Main(receiver) => Ok(receiver.poll_session(Instant::now())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn poll_keepalive(&mut self, mac: [u8; 6]) -> Result<Option<usize>> {
        match self {
            Self::Main(receiver) => Ok(receiver
                .poll_session_and_send_keepalive(
                    Instant::now(),
                    rist_core::packet::gre::GreKeepalive::librist_default(mac),
                )?
                .keepalive
                .map(|packet| packet.bytes.len())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn try_recv_eapol_and_respond(&mut self, buf: &mut [u8]) -> Result<Option<()>> {
        match self {
            Self::Main(receiver) => Ok(receiver.try_recv_eapol_and_respond(buf)?.map(|_| ())),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn srp_authenticated(&self) -> bool {
        match self {
            Self::Main(receiver) => receiver.srp_authenticated(),
            Self::Simple(_) => true,
        }
    }

    pub fn stage_srp_password(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> Result<SrpUserRecord> {
        match self {
            Self::Main(receiver) => Ok(receiver.stage_srp_password(username, password)?),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn retire_srp_generations_before(&mut self, username: &str, generation: u64) -> Result<()> {
        match self {
            Self::Main(receiver) => {
                Ok(receiver.retire_srp_generations_before(username, generation)?)
            }
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn current_srp_generation(&self, username: &str) -> Option<u64> {
        match self {
            Self::Main(receiver) => receiver.current_srp_generation(username),
            Self::Simple(_) => None,
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(match self {
            Self::Simple(receiver) => receiver.local_addr()?,
            Self::Main(receiver) => receiver.local_addr()?,
        })
    }

    pub fn missing_sequences(&self) -> Vec<u32> {
        match self {
            Self::Simple(receiver) => receiver.missing_sequences(),
            Self::Main(receiver) => receiver.missing_sequences(),
        }
    }

    pub fn stats(&self) -> ReceiverStats {
        match self {
            Self::Simple(receiver) => receiver.stats(),
            Self::Main(receiver) => receiver.stats(),
        }
    }
}

fn loopback_any() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn resolve_endpoint(endpoint: &Endpoint) -> Result<SocketAddr> {
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    address
        .to_socket_addrs()?
        .next()
        .ok_or(Error::AddressResolution(address))
}

fn parse_miface_v4(miface: Option<&str>) -> Result<Option<Ipv4Addr>> {
    Ok(miface.and_then(|value| value.parse().ok()))
}

fn parse_nonnegative_i32(value: Option<i32>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_core::packet::gre::{KeepalivePacket, ReducedPacket};
    use rist_core::packet::rtp::RtpPacket;
    use std::thread;
    use std::time::{Duration, Instant};

    fn recv_eventually(receiver: &mut Receiver, buf: &mut [u8]) -> ReceivedPayload {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(payload) = receiver.recv(buf).unwrap() {
                return payload;
            }
            assert!(Instant::now() < deadline, "timed out waiting for payload");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_raw_main_payload(socket: &std::net::UdpSocket, buf: &mut [u8]) -> Vec<u8> {
        let (len, _) = socket.recv_from(buf).unwrap();
        let reduced = ReducedPacket::decode(&buf[..len]).unwrap();
        let rtp = RtpPacket::decode(reduced.payload).unwrap();
        rtp.payload.to_vec()
    }

    fn drive_srp_authentication(
        sender: &mut Sender,
        receiver: &mut Receiver,
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

    #[test]
    fn simple_sender_receiver_round_trip_through_builder() {
        let flow_id = 0x1122_3344;
        let mut receiver = Receiver::builder(Profile::Simple)
            .flow_id(flow_id)
            .bind()
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender = Sender::builder(Profile::Simple)
            .peer_addr(receiver_addr)
            .flow_id(flow_id)
            .connect()
            .unwrap();

        assert_eq!(sender.send(b"payload").unwrap(), 7);

        let mut buf = [0; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"payload");
    }

    #[test]
    fn main_sender_receiver_round_trip_with_url_psk() {
        let flow_id = 0x1122_3344;
        let mut receiver = Receiver::builder(Profile::Main)
            .flow_id(flow_id)
            .psk(256, b"secret")
            .bind()
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let url = format!(
            "rist://127.0.0.1:{}?secret=secret&aes-type=256",
            receiver_addr.port()
        );
        let mut sender = Sender::builder(Profile::Main)
            .peer_url(&url)
            .unwrap()
            .flow_id(flow_id)
            .connect()
            .unwrap();

        assert_eq!(sender.send(b"payload").unwrap(), 7);

        let mut buf = [0; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"payload");
    }

    #[test]
    fn advanced_profile_round_trip_uses_main_compatible_subset() {
        let flow_id = 0x1122_3344;
        let mut receiver = Receiver::builder(Profile::Advanced)
            .flow_id(flow_id)
            .bind()
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender = Sender::builder(Profile::Advanced)
            .peer_addr(receiver_addr)
            .flow_id(flow_id)
            .connect()
            .unwrap();

        assert_eq!(sender.send(b"advanced-subset").unwrap(), 15);

        let mut buf = [0; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"advanced-subset");
    }

    #[test]
    fn main_sender_receiver_round_trip_with_url_srp() {
        let flow_id = 0x1122_3344;
        let mut receiver = Receiver::builder(Profile::Main)
            .listen_url("rist://@:0?username=rist&password=secret")
            .unwrap()
            .flow_id(flow_id)
            .bind()
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let url = format!(
            "rist://127.0.0.1:{}?username=rist&password=secret",
            receiver_addr.port()
        );
        let mut sender = Sender::builder(Profile::Main)
            .peer_url(&url)
            .unwrap()
            .flow_id(flow_id)
            .connect()
            .unwrap();

        assert!(sender.send(b"too-early").is_err());
        sender.start_srp_authentication().unwrap();
        let mut sender_buf = [0u8; 1500];
        let mut receiver_buf = [0u8; 1500];
        drive_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );

        assert_eq!(sender.send(b"payload").unwrap(), 7);

        let mut buf = [0; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"payload");
    }

    #[test]
    fn main_sender_url_virtual_ports_affect_reduced_header() {
        let raw_receiver = std::net::UdpSocket::bind(loopback_any()).unwrap();
        raw_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let url = format!(
            "rist://127.0.0.1:{}?virt-src-port=9000&virt-dst-port=9001&rtp-sequence=77",
            raw_receiver.local_addr().unwrap().port()
        );
        let mut sender = Sender::builder(Profile::Main)
            .peer_url(&url)
            .unwrap()
            .connect()
            .unwrap();

        sender.send(b"payload").unwrap();

        let mut buf = [0u8; 1500];
        let (len, _) = raw_receiver.recv_from(&mut buf).unwrap();
        let reduced = ReducedPacket::decode(&buf[..len]).unwrap();
        assert_eq!(reduced.reduced.src_port, 9000);
        assert_eq!(reduced.reduced.dst_port, 9001);
        let rtp = RtpPacket::decode(reduced.payload).unwrap();
        assert_eq!(rtp.header.sequence_number, 77);
    }

    #[test]
    fn main_sender_url_keepalive_interval_drives_poll_keepalive() {
        let raw_receiver = std::net::UdpSocket::bind(loopback_any()).unwrap();
        raw_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let url = format!(
            "rist://127.0.0.1:{}?keepalive-interval=0&session-timeout=50",
            raw_receiver.local_addr().unwrap().port()
        );
        let mut sender = Sender::builder(Profile::Main)
            .peer_url(&url)
            .unwrap()
            .connect()
            .unwrap();

        assert!(sender.poll_keepalive([1, 2, 3, 4, 5, 6]).unwrap().is_some());

        let mut buf = [0u8; 1500];
        let (len, _) = raw_receiver.recv_from(&mut buf).unwrap();
        let keepalive = KeepalivePacket::decode(&buf[..len]).unwrap();
        assert_eq!(keepalive.gre.sequence, Some(0));
        assert_eq!(keepalive.keepalive.mac, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn main_multi_sender_uses_url_weights() {
        let rx_a = std::net::UdpSocket::bind(loopback_any()).unwrap();
        let rx_b = std::net::UdpSocket::bind(loopback_any()).unwrap();
        rx_a.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        rx_b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let url_a = format!(
            "rist://127.0.0.1:{}?weight=0",
            rx_a.local_addr().unwrap().port()
        );
        let url_b = format!(
            "rist://127.0.0.1:{}?weight=0",
            rx_b.local_addr().unwrap().port()
        );
        let mut sender = MultiSender::builder(Profile::Main)
            .peer_url(&url_a)
            .unwrap()
            .peer_url(&url_b)
            .unwrap()
            .connect()
            .unwrap();

        assert_eq!(sender.send(b"duplicate").unwrap(), vec![0, 1]);

        let mut buf_a = [0u8; 1500];
        let mut buf_b = [0u8; 1500];
        assert_eq!(recv_raw_main_payload(&rx_a, &mut buf_a), b"duplicate");
        assert_eq!(recv_raw_main_payload(&rx_b, &mut buf_b), b"duplicate");
    }
}
