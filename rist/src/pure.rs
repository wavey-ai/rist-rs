//! Pure Rust RIST implementation surface.
//!
//! This module is available with the `pure-rust` feature. It exposes the
//! sans-I/O protocol core and the Mio UDP transport without going through
//! librist FFI.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod core {
    pub use rist_core::*;
}

pub mod mio {
    pub use rist_mio::{
        MainMioMultiSend, MainMioMultiSender, MainMioPeer, MainMioPeerControlPacket,
        MainMioPeerPacket, MainMioReceiver, MainMioSender, MainMioSessionPoll, MainSenderEvent,
        NetworkInterface, RtpUdpSocket, SimpleMioReceiver, SimpleMioSender,
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

    #[error("RIST URL option {0} is not implemented by this pure Rust builder")]
    UnsupportedUrlOption(String),

    #[error("RIST URL profile {url:?} does not match builder profile {builder:?}")]
    UrlProfileMismatch { builder: Profile, url: Profile },

    #[error("sender peer address is missing")]
    MissingPeer,

    #[error("URL must be a sender peer URL")]
    ExpectedPeerUrl,

    #[error("URL must be a receiver listen URL")]
    ExpectedListenUrl,

    #[error("address did not resolve: {0}")]
    AddressResolution(String),

    #[error("invalid multicast configuration: {0}")]
    InvalidMulticastConfig(String),

    #[error(transparent)]
    OrderedOutput(#[from] rist_core::OrderedPayloadBufferError),
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct SenderBuilder {
    profile: Profile,
    local: SocketAddr,
    local_explicit: bool,
    peer: Option<SocketAddr>,
    listening: bool,
    flow_id: u32,
    history_packets: usize,
    virtual_ports: VirtualPorts,
    session_config: MainSessionConfig,
    network_interface: rist_mio::NetworkInterface,
    multicast_ttl: Option<u8>,
    multicast_loopback: bool,
    local_port: Option<u16>,
    initial_rtp_sequence: Option<u32>,
    null_packet_suppression: bool,
    psk: Option<PskOptions>,
    srp_client: Option<(String, Vec<u8>)>,
    srp_store: Option<SrpCredentialStore>,
    srp_compat_legacy: bool,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
}

impl SenderBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            local_explicit: false,
            peer: None,
            listening: false,
            flow_id: 0x1122_3344,
            history_packets: 1024,
            virtual_ports: VirtualPorts::default(),
            session_config: MainSessionConfig::default(),
            network_interface: rist_mio::NetworkInterface::Default,
            multicast_ttl: None,
            multicast_loopback: true,
            local_port: None,
            initial_rtp_sequence: None,
            null_packet_suppression: false,
            psk: None,
            srp_client: None,
            srp_store: None,
            srp_compat_legacy: false,
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self.local_explicit = true;
        self
    }

    pub fn peer_addr(mut self, peer: SocketAddr) -> Self {
        if !self.local_explicit {
            self.local = default_local_for_peer(peer);
        }
        self.peer = Some(peer);
        self.listening = false;
        self
    }

    pub fn listen_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self.local_explicit = true;
        self.peer = None;
        self.listening = true;
        self
    }

    pub fn peer_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if config.endpoint.listen {
            return Err(Error::ExpectedPeerUrl);
        }
        validate_url_options(
            &config,
            self.profile,
            &[
                "secret",
                "aes-type",
                "key-rotation",
                "username",
                "password",
                "srp-compat",
                "miface",
                "ttl",
                "local-port",
                "rtp-sequence",
                "virt-src-port",
                "virt-dst-port",
                "session-timeout",
                "keepalive-interval",
                "profile",
                "buffer",
                "bandwidth",
                "return-bandwidth",
                "buffer-min",
                "buffer-max",
                "reorder-buffer",
                "rtt",
                "rtt-min",
                "rtt-max",
                "min-retries",
                "max-retries",
                "congestion-control",
            ],
        )?;
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            self.srp_client = Some((username.clone(), password.as_bytes().to_vec()));
            self.srp_store = None;
        }
        self.srp_compat_legacy = config.srp_compat_legacy;
        self.network_interface = parse_network_interface(config.endpoint.miface.as_deref());
        self.multicast_ttl = config.endpoint.multicast_ttl;
        self.local_port = config.endpoint.local_port;
        self.initial_rtp_sequence = parse_nonnegative_i32(config.advanced.rtp_sequence);
        self.virtual_ports = config.virtual_ports;
        self.session_config = config.connection.into();
        self.recovery = config.recovery;
        self.congestion_control = config.congestion_control;
        let peer = resolve_endpoint(&config.endpoint, self.local_explicit.then_some(self.local))?;
        self.peer = Some(peer);
        self.listening = false;
        Ok(self)
    }

    pub fn listen_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if !config.endpoint.listen {
            return Err(Error::ExpectedListenUrl);
        }
        validate_url_options(
            &config,
            self.profile,
            &[
                "secret",
                "aes-type",
                "key-rotation",
                "username",
                "password",
                "srp-compat",
                "rtp-sequence",
                "virt-src-port",
                "virt-dst-port",
                "session-timeout",
                "keepalive-interval",
                "profile",
                "buffer",
                "bandwidth",
                "return-bandwidth",
                "buffer-min",
                "buffer-max",
                "reorder-buffer",
                "rtt",
                "rtt-min",
                "rtt-max",
                "min-retries",
                "max-retries",
                "congestion-control",
            ],
        )?;
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            let mut store = SrpCredentialStore::new();
            store.stage_password(username, password.as_bytes())?;
            self.srp_store = Some(store);
            self.srp_client = None;
        }
        self.srp_compat_legacy = config.srp_compat_legacy;
        self.initial_rtp_sequence = parse_nonnegative_i32(config.advanced.rtp_sequence);
        self.virtual_ports = config.virtual_ports;
        self.session_config = config.connection.into();
        self.recovery = config.recovery;
        self.congestion_control = config.congestion_control;
        self.local = resolve_endpoint(&config.endpoint, None)?;
        self.local_explicit = true;
        self.peer = None;
        self.listening = true;
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
        self.network_interface = rist_mio::NetworkInterface::Address(IpAddr::V4(interface));
        self
    }

    pub fn network_interface(mut self, interface: rist_mio::NetworkInterface) -> Self {
        self.network_interface = interface;
        self
    }

    pub fn multicast_ttl(mut self, ttl: u8) -> Self {
        self.multicast_ttl = Some(ttl);
        self
    }

    pub fn multicast_loopback(mut self, enabled: bool) -> Self {
        self.multicast_loopback = enabled;
        self
    }

    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
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

    pub fn srp_store(mut self, store: SrpCredentialStore) -> Self {
        self.srp_store = Some(store);
        self
    }

    pub fn connect(mut self) -> Result<Sender> {
        let mut peer = if self.listening {
            None
        } else {
            Some(self.peer.ok_or(Error::MissingPeer)?)
        };
        if let Some(peer) = &mut peer {
            configure_peer_network(
                &mut self.local,
                self.local_explicit,
                peer,
                &self.network_interface,
                self.local_port,
            )?;
            if self.multicast_ttl.is_some() && !peer.ip().is_multicast() {
                return Err(Error::InvalidMulticastConfig(
                    "ttl requires a multicast peer".to_string(),
                ));
            }
        } else if let Some(port) = self.local_port {
            self.local.set_port(port);
        }
        if self.multicast_ttl == Some(0) {
            return Err(Error::InvalidMulticastConfig(
                "multicast TTL or hop limit must be between 1 and 255".to_string(),
            ));
        }
        match self.profile {
            Profile::Simple => {
                let mut sender = match peer {
                    Some(peer) => rist_mio::SimpleMioSender::connect(
                        self.local,
                        peer,
                        self.flow_id,
                        self.history_packets,
                    )?,
                    None => rist_mio::SimpleMioSender::listen(
                        self.local,
                        self.flow_id,
                        self.history_packets,
                    )?,
                };
                if peer.is_some_and(|peer| peer.ip().is_multicast()) {
                    sender.configure_multicast(
                        &self.network_interface,
                        self.multicast_ttl,
                        self.multicast_loopback,
                    )?;
                }
                if let Some(sequence) = self.initial_rtp_sequence {
                    sender.set_next_sequence(sequence);
                }
                sender.set_recovery_config(self.recovery, self.congestion_control);
                if self.null_packet_suppression {
                    sender.enable_null_packet_suppression();
                }
                Ok(Sender::Simple(sender))
            }
            Profile::Main => {
                let mut sender = match peer {
                    Some(peer) => rist_mio::MainMioSender::connect(
                        self.local,
                        peer,
                        self.flow_id,
                        self.history_packets,
                    )?,
                    None => rist_mio::MainMioSender::listen(
                        self.local,
                        self.flow_id,
                        self.history_packets,
                    )?,
                };
                sender.set_ports(self.virtual_ports.src, self.virtual_ports.dst);
                sender.set_session_config(self.session_config);
                sender.set_recovery_config(self.recovery, self.congestion_control);
                if peer.is_some_and(|peer| peer.ip().is_multicast()) {
                    sender.configure_multicast(
                        &self.network_interface,
                        self.multicast_ttl,
                        self.multicast_loopback,
                    )?;
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
                if let Some(store) = self.srp_store {
                    sender.set_srp_authenticator_session(
                        rist_core::EapSrpAuthenticatorSession::new(store)
                            .with_session_key_passphrase(false)
                            .with_srp_compat_legacy(self.srp_compat_legacy),
                    );
                } else if let Some((username, password)) = self.srp_client {
                    sender.set_srp_client_session(
                        rist_core::EapSrpClientSession::new(username, password)
                            .with_session_key_passphrase(false)
                            .with_srp_compat_legacy(self.srp_compat_legacy),
                    );
                }
                Ok(Sender::Main(sender))
            }
            Profile::Advanced => Err(Error::UnsupportedProfile(Profile::Advanced)),
        }
    }
}

#[allow(clippy::large_enum_variant)]
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

    pub fn listen(profile: Profile, local: SocketAddr, flow_id: u32) -> Result<Self> {
        Self::builder(profile)
            .listen_addr(local)
            .flow_id(flow_id)
            .connect()
    }

    pub fn listen_url(profile: Profile, url: &str) -> Result<Self> {
        Self::builder(profile).listen_url(url)?.connect()
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

#[derive(Clone)]
pub struct MultiSenderBuilder {
    profile: Profile,
    local: SocketAddr,
    local_explicit: bool,
    peers: Vec<MultiSenderPeer>,
    flow_id: u32,
    history_packets: usize,
    virtual_ports: VirtualPorts,
    session_config: MainSessionConfig,
    multicast_interface_v4: Option<Ipv4Addr>,
    initial_rtp_sequence: Option<u32>,
    null_packet_suppression: bool,
    psk: Option<PskOptions>,
    srp_client: Option<(String, Vec<u8>)>,
    srp_compat_legacy: bool,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
}

impl MultiSenderBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            local_explicit: false,
            peers: Vec::new(),
            flow_id: 0x1122_3344,
            history_packets: 1024,
            virtual_ports: VirtualPorts::default(),
            session_config: MainSessionConfig::default(),
            multicast_interface_v4: None,
            initial_rtp_sequence: None,
            null_packet_suppression: false,
            psk: None,
            srp_client: None,
            srp_compat_legacy: false,
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self.local_explicit = true;
        self
    }

    pub fn peer_addr(mut self, peer: SocketAddr, weight: u32) -> Self {
        if !self.local_explicit && self.peers.is_empty() {
            self.local = default_local_for_peer(peer);
        }
        self.peers.push(MultiSenderPeer { addr: peer, weight });
        self
    }

    pub fn peer_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if config.endpoint.listen {
            return Err(Error::ExpectedPeerUrl);
        }
        validate_url_options(
            &config,
            self.profile,
            &[
                "secret",
                "aes-type",
                "key-rotation",
                "username",
                "password",
                "srp-compat",
                "miface",
                "rtp-sequence",
                "virt-src-port",
                "virt-dst-port",
                "session-timeout",
                "keepalive-interval",
                "weight",
                "profile",
                "buffer",
                "bandwidth",
                "return-bandwidth",
                "buffer-min",
                "buffer-max",
                "reorder-buffer",
                "rtt",
                "rtt-min",
                "rtt-max",
                "min-retries",
                "max-retries",
                "congestion-control",
            ],
        )?;
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            self.srp_client = Some((username.clone(), password.as_bytes().to_vec()));
        }
        self.srp_compat_legacy = config.srp_compat_legacy;
        self.multicast_interface_v4 = parse_miface_v4(config.endpoint.miface.as_deref())?;
        self.initial_rtp_sequence = parse_nonnegative_i32(config.advanced.rtp_sequence);
        self.virtual_ports = config.virtual_ports;
        self.session_config = config.connection.into();
        self.recovery = config.recovery;
        self.congestion_control = config.congestion_control;
        let preferred = if self.local_explicit {
            Some(self.local)
        } else {
            self.peers.first().map(|peer| peer.addr)
        };
        let peer = resolve_endpoint(&config.endpoint, preferred)?;
        if !self.local_explicit && self.peers.is_empty() {
            self.local = default_local_for_peer(peer);
        }
        self.peers.push(MultiSenderPeer {
            addr: peer,
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

    pub fn srp_client(mut self, username: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        self.srp_client = Some((username.into(), password.as_ref().to_vec()));
        self
    }

    pub fn connect(self) -> Result<MultiSender> {
        if self.peers.is_empty() {
            return Err(Error::MissingPeer);
        }
        match self.profile {
            Profile::Main => {
                let mut sender = rist_mio::MainMioMultiSender::bind(
                    self.local,
                    self.flow_id,
                    self.history_packets,
                )?;
                sender.set_ports(self.virtual_ports.src, self.virtual_ports.dst);
                sender.set_session_config(self.session_config);
                sender.set_recovery_config(self.recovery, self.congestion_control);
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
                    sender.set_srp_client_session(
                        rist_core::EapSrpClientSession::new(username, password)
                            .with_session_key_passphrase(false)
                            .with_srp_compat_legacy(self.srp_compat_legacy),
                    );
                }
                for peer in self.peers {
                    sender.add_peer(peer.addr, peer.weight)?;
                }
                Ok(MultiSender::Main(sender))
            }
            Profile::Simple => Err(Error::UnsupportedProfile(Profile::Simple)),
            Profile::Advanced => Err(Error::UnsupportedProfile(Profile::Advanced)),
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

    pub fn start_srp_authentication(&mut self) -> Result<Vec<usize>> {
        match self {
            Self::Main(sender) => Ok(sender
                .start_srp_authentication_all()?
                .into_iter()
                .map(|packet| packet.peer)
                .collect()),
        }
    }

    pub fn try_recv_event(&mut self, buf: &mut [u8]) -> Result<Option<rist_mio::MainSenderEvent>> {
        match self {
            Self::Main(sender) => Ok(sender.try_recv_event(buf)?),
        }
    }

    pub fn try_recv_feedback_and_retransmit(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self {
            Self::Main(sender) => Ok(sender
                .try_recv_feedback_and_retransmit(buf)?
                .map(|packets| packets.len())),
        }
    }

    pub fn peer_srp_authenticated(&self, peer: usize) -> Option<bool> {
        match self {
            Self::Main(sender) => sender.peer_srp_authenticated(peer),
        }
    }

    pub fn srp_authenticated(&self) -> bool {
        match self {
            Self::Main(sender) => sender.srp_authenticated(),
        }
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> Result<()> {
        match self {
            Self::Main(sender) => Ok(sender.update_srp_client_password(password)?),
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

#[derive(Clone)]
pub struct ReceiverBuilder {
    profile: Profile,
    local: SocketAddr,
    local_explicit: bool,
    peer: Option<SocketAddr>,
    listening: bool,
    flow_id: u32,
    cname: String,
    nack_mode: rist_core::packet::rtcp::NackMode,
    session_config: MainSessionConfig,
    psk: Option<PskOptions>,
    srp_store: Option<SrpCredentialStore>,
    srp_client: Option<(String, Vec<u8>)>,
    srp_compat_legacy: bool,
    recovery: RecoveryConfig,
    congestion_control: CongestionControlMode,
    network_interface: rist_mio::NetworkInterface,
    multicast_group: Option<IpAddr>,
    multicast_source: Option<Ipv4Addr>,
    local_port: Option<u16>,
}

impl ReceiverBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: loopback_any(),
            local_explicit: false,
            peer: None,
            listening: true,
            flow_id: 0x1122_3344,
            cname: "rust".to_string(),
            nack_mode: rist_core::packet::rtcp::NackMode::Range,
            session_config: MainSessionConfig::default(),
            psk: None,
            srp_store: None,
            srp_client: None,
            srp_compat_legacy: false,
            recovery: RecoveryConfig::default(),
            congestion_control: CongestionControlMode::default(),
            network_interface: rist_mio::NetworkInterface::Default,
            multicast_group: None,
            multicast_source: None,
            local_port: None,
        }
    }

    pub fn local_addr(mut self, local: SocketAddr) -> Self {
        self.local = local;
        self.local_explicit = true;
        self
    }

    pub fn peer_addr(mut self, peer: SocketAddr) -> Self {
        if !self.local_explicit {
            self.local = default_local_for_peer(peer);
        }
        self.peer = Some(peer);
        self.listening = false;
        self
    }

    pub fn listen_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if !config.endpoint.listen {
            return Err(Error::ExpectedListenUrl);
        }
        validate_url_options(
            &config,
            self.profile,
            &[
                "cname",
                "secret",
                "aes-type",
                "key-rotation",
                "username",
                "password",
                "srp-compat",
                "miface",
                "source",
                "session-timeout",
                "keepalive-interval",
                "profile",
                "buffer",
                "bandwidth",
                "return-bandwidth",
                "buffer-min",
                "buffer-max",
                "reorder-buffer",
                "rtt",
                "rtt-min",
                "rtt-max",
                "min-retries",
                "max-retries",
                "congestion-control",
            ],
        )?;
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
            self.srp_client = None;
        }
        self.srp_compat_legacy = config.srp_compat_legacy;
        self.session_config = config.connection.into();
        self.recovery = config.recovery;
        self.congestion_control = config.congestion_control;
        self.network_interface = parse_network_interface(config.endpoint.miface.as_deref());
        self.multicast_source = config.endpoint.multicast_source;
        let endpoint = resolve_endpoint(&config.endpoint, None)?;
        if endpoint.ip().is_multicast() {
            if endpoint.is_ipv6() && self.multicast_source.is_some() {
                return Err(Error::InvalidMulticastConfig(
                    "current librist supports source-specific multicast only for IPv4".to_string(),
                ));
            }
            self.multicast_group = Some(endpoint.ip());
            self.local = unspecified_for(endpoint);
        } else {
            if self.multicast_source.is_some() {
                return Err(Error::InvalidMulticastConfig(
                    "source requires an IPv4 multicast listen address".to_string(),
                ));
            }
            if config.endpoint.miface.is_some() {
                return Err(Error::UnsupportedUrlOption("miface".to_string()));
            }
            self.multicast_group = None;
            self.local = endpoint;
        }
        self.local_explicit = true;
        self.peer = None;
        self.listening = true;
        Ok(self)
    }

    pub fn peer_url(mut self, url: &str) -> Result<Self> {
        let config = PeerConfig::parse(url)?;
        if config.endpoint.listen {
            return Err(Error::ExpectedPeerUrl);
        }
        validate_url_options(
            &config,
            self.profile,
            &[
                "cname",
                "secret",
                "aes-type",
                "key-rotation",
                "username",
                "password",
                "srp-compat",
                "miface",
                "local-port",
                "session-timeout",
                "keepalive-interval",
                "profile",
                "buffer",
                "bandwidth",
                "return-bandwidth",
                "buffer-min",
                "buffer-max",
                "reorder-buffer",
                "rtt",
                "rtt-min",
                "rtt-max",
                "min-retries",
                "max-retries",
                "congestion-control",
            ],
        )?;
        if let Some(cname) = config.cname {
            self.cname = cname;
        }
        if let Some(encryption) = &config.encryption {
            self.psk = Some(PskOptions::from_config(encryption));
        }
        if let (Some(username), Some(password)) = (&config.srp_username, &config.srp_password) {
            self.srp_client = Some((username.clone(), password.as_bytes().to_vec()));
            self.srp_store = None;
        }
        self.srp_compat_legacy = config.srp_compat_legacy;
        self.session_config = config.connection.into();
        self.recovery = config.recovery;
        self.congestion_control = config.congestion_control;
        self.network_interface = parse_network_interface(config.endpoint.miface.as_deref());
        self.local_port = config.endpoint.local_port;
        let peer = resolve_endpoint(&config.endpoint, self.local_explicit.then_some(self.local))?;
        if peer.ip().is_multicast() {
            return Err(Error::InvalidMulticastConfig(
                "multicast receivers must use a listen URL".to_string(),
            ));
        }
        self.peer = Some(peer);
        self.listening = false;
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

    pub fn network_interface(mut self, interface: rist_mio::NetworkInterface) -> Self {
        self.network_interface = interface;
        self
    }

    pub fn multicast_interface_v4(mut self, interface: Ipv4Addr) -> Self {
        self.network_interface = rist_mio::NetworkInterface::Address(IpAddr::V4(interface));
        self
    }

    pub fn multicast_source_v4(mut self, source: Ipv4Addr) -> Self {
        self.multicast_source = Some(source);
        self
    }

    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    pub fn listen_multicast(mut self, group: SocketAddr) -> Self {
        self.multicast_group = Some(group.ip());
        self.local = unspecified_for(group);
        self.local_explicit = true;
        self.peer = None;
        self.listening = true;
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

    pub fn srp_client(mut self, username: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        self.srp_client = Some((username.into(), password.as_ref().to_vec()));
        self
    }

    pub fn bind(mut self) -> Result<Receiver> {
        let mut peer = if self.listening {
            None
        } else {
            Some(self.peer.ok_or(Error::MissingPeer)?)
        };
        if let Some(peer) = &mut peer {
            configure_peer_network(
                &mut self.local,
                self.local_explicit,
                peer,
                &self.network_interface,
                self.local_port,
            )?;
        } else if let Some(port) = self.local_port {
            self.local.set_port(port);
        }
        if self.multicast_source.is_some()
            && !self
                .multicast_group
                .is_some_and(|group| matches!(group, IpAddr::V4(_)))
        {
            return Err(Error::InvalidMulticastConfig(
                "source requires an IPv4 multicast listen address".to_string(),
            ));
        }
        match self.profile {
            Profile::Simple => {
                let mut receiver = match peer {
                    Some(peer) => rist_mio::SimpleMioReceiver::connect(
                        self.local,
                        peer,
                        self.flow_id,
                        self.cname,
                        self.nack_mode,
                    )?,
                    None if self.multicast_group.is_some() => {
                        rist_mio::SimpleMioReceiver::bind_reuse(
                            self.local,
                            self.flow_id,
                            self.cname,
                            self.nack_mode,
                        )?
                    }
                    None => rist_mio::SimpleMioReceiver::bind(
                        self.local,
                        self.flow_id,
                        self.cname,
                        self.nack_mode,
                    )?,
                };
                receiver.set_recovery_config(self.recovery, self.congestion_control);
                if let Some(group) = self.multicast_group {
                    receiver.join_multicast(
                        group,
                        &self.network_interface,
                        self.multicast_source,
                    )?;
                }
                Ok(Receiver::Simple(receiver))
            }
            Profile::Main => {
                let mut receiver = match peer {
                    Some(peer) => rist_mio::MainMioReceiver::connect(
                        self.local,
                        peer,
                        self.flow_id,
                        self.cname,
                        self.nack_mode,
                    )?,
                    None if self.multicast_group.is_some() => {
                        rist_mio::MainMioReceiver::bind_reuse(
                            self.local,
                            self.flow_id,
                            self.cname,
                            self.nack_mode,
                        )?
                    }
                    None => rist_mio::MainMioReceiver::bind(
                        self.local,
                        self.flow_id,
                        self.cname,
                        self.nack_mode,
                    )?,
                };
                receiver.set_session_config(self.session_config);
                receiver.set_recovery_config(self.recovery, self.congestion_control);
                if let Some(group) = self.multicast_group {
                    receiver.join_multicast(
                        group,
                        &self.network_interface,
                        self.multicast_source,
                    )?;
                }
                if let Some(psk) = self.psk {
                    receiver.set_tx_key(psk.tx_key()?);
                    receiver.set_rx_key(psk.rx_key()?);
                }
                if let Some((username, password)) = self.srp_client {
                    receiver.set_srp_client_session(
                        rist_core::EapSrpClientSession::new(username, password)
                            .with_session_key_passphrase(false)
                            .with_srp_compat_legacy(self.srp_compat_legacy),
                    );
                } else if let Some(store) = self.srp_store {
                    receiver.set_srp_authenticator_session(
                        rist_core::EapSrpAuthenticatorSession::new(store)
                            .with_session_key_passphrase(false)
                            .with_srp_compat_legacy(self.srp_compat_legacy),
                    );
                }
                Ok(Receiver::Main(receiver))
            }
            Profile::Advanced => Err(Error::UnsupportedProfile(Profile::Advanced)),
        }
    }
}

#[allow(clippy::large_enum_variant)]
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

    pub fn connect(
        profile: Profile,
        local: SocketAddr,
        peer: SocketAddr,
        flow_id: u32,
    ) -> Result<Self> {
        Self::builder(profile)
            .local_addr(local)
            .peer_addr(peer)
            .flow_id(flow_id)
            .bind()
    }

    pub fn connect_url(profile: Profile, url: &str) -> Result<Self> {
        Self::builder(profile).peer_url(url)?.bind()
    }

    /// Converts packet-arrival output into deadline-aware wire-order output.
    pub fn into_ordered(
        self,
        max_pending_packets: usize,
        reorder_delay: Duration,
    ) -> OrderedReceiver {
        OrderedReceiver {
            receiver: self,
            ordering: rist_core::OrderedPayloadBuffer::with_reorder_delay(
                max_pending_packets,
                reorder_delay,
            ),
            ready: VecDeque::new(),
        }
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

    pub fn start_srp_authentication(&mut self) -> Result<usize> {
        match self {
            Self::Main(receiver) => Ok(receiver.start_srp_authentication()?.bytes.len()),
            Self::Simple(_) => Err(Error::UnsupportedProfile(Profile::Simple)),
        }
    }

    pub fn update_srp_client_password(&mut self, password: impl AsRef<[u8]>) -> Result<()> {
        match self {
            Self::Main(receiver) => Ok(receiver.update_srp_client_password(password)?),
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

/// Deadline-aware ordered adapter for a pure packet receiver.
pub struct OrderedReceiver {
    receiver: Receiver,
    ordering: rist_core::OrderedPayloadBuffer,
    ready: VecDeque<ReceivedPayload>,
}

impl OrderedReceiver {
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Option<ReceivedPayload>> {
        if let Some(payload) = self.ready.pop_front() {
            return Ok(Some(payload));
        }

        let now = Instant::now();
        if let Some(payload) = self.receiver.recv(buf)? {
            self.ready.extend(self.ordering.push_at(payload, now)?);
        } else {
            self.ready.extend(self.ordering.release_expired(now));
        }
        Ok(self.ready.pop_front())
    }

    pub fn receiver(&self) -> &Receiver {
        &self.receiver
    }

    pub fn receiver_mut(&mut self) -> &mut Receiver {
        &mut self.receiver
    }
}

fn loopback_any() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn default_local_for_peer(peer: SocketAddr) -> SocketAddr {
    let ip = match peer.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(ip) if ip.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

fn unspecified_for(address: SocketAddr) -> SocketAddr {
    let ip = if address.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, address.port())
}

fn resolve_endpoint(endpoint: &Endpoint, preferred: Option<SocketAddr>) -> Result<SocketAddr> {
    let address = format_endpoint(endpoint);
    let addresses = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()?
        .collect::<Vec<_>>();
    if let Some(preferred) = preferred {
        return addresses
            .into_iter()
            .find(|address| address.is_ipv4() == preferred.is_ipv4())
            .ok_or(Error::AddressResolution(address));
    }
    addresses
        .into_iter()
        .next()
        .ok_or(Error::AddressResolution(address))
}

fn format_endpoint(endpoint: &Endpoint) -> String {
    if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    }
}

fn parse_network_interface(miface: Option<&str>) -> rist_mio::NetworkInterface {
    miface.map_or(rist_mio::NetworkInterface::Default, |value| {
        rist_mio::NetworkInterface::from_miface(value)
    })
}

fn configure_peer_network(
    local: &mut SocketAddr,
    local_explicit: bool,
    peer: &mut SocketAddr,
    interface: &rist_mio::NetworkInterface,
    local_port: Option<u16>,
) -> Result<()> {
    if let SocketAddr::V6(peer_v6) = peer {
        if peer_v6.ip().is_multicast() && peer_v6.scope_id() == 0 {
            let interface_index = rist_mio::network_interface_index(interface)?;
            if interface_index != 0 {
                peer_v6.set_scope_id(interface_index);
            }
        }
    }
    if !local_explicit {
        *local = if matches!(interface, rist_mio::NetworkInterface::Default) {
            default_local_for_peer(*peer)
        } else {
            SocketAddr::new(
                rist_mio::network_interface_address(interface, peer.is_ipv4())?,
                0,
            )
        };
    }
    if let Some(port) = local_port {
        local.set_port(port);
    }
    Ok(())
}

fn parse_miface_v4(miface: Option<&str>) -> Result<Option<Ipv4Addr>> {
    Ok(miface.and_then(|value| value.parse().ok()))
}

fn parse_nonnegative_i32(value: Option<i32>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

fn validate_url_options(
    config: &PeerConfig,
    builder_profile: Profile,
    supported: &[&str],
) -> Result<()> {
    if let Some(url_profile) = config.advanced.profile {
        if url_profile != builder_profile {
            return Err(Error::UrlProfileMismatch {
                builder: builder_profile,
                url: url_profile,
            });
        }
    }
    if let Some(option) = config
        .specified_options
        .iter()
        .find(|option| !supported.contains(&option.as_str()))
    {
        return Err(Error::UnsupportedUrlOption(option.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_core::packet::gre::{KeepalivePacket, ReducedPacket};
    use rist_core::packet::rtp::RtpPacket;
    use std::net::UdpSocket;
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

    fn loopback_miface() -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "lo0"
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            "lo"
        }
        #[cfg(not(unix))]
        {
            "127.0.0.1"
        }
    }

    fn next_even_port_pair() -> u16 {
        for _ in 0..128 {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = socket.local_addr().unwrap().port();
            drop(socket);
            let base = if port % 2 == 0 {
                port
            } else {
                port.saturating_add(1)
            };
            if base == u16::MAX {
                continue;
            }
            if let (Ok(_rtp), Ok(_rtcp)) = (
                UdpSocket::bind((Ipv4Addr::LOCALHOST, base)),
                UdpSocket::bind((Ipv4Addr::LOCALHOST, base + 1)),
            ) {
                return base;
            }
        }
        panic!("failed to allocate an even UDP port pair");
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
    fn simple_receiver_caller_round_trip_through_builder() {
        let flow_id = 0x1122_3344;
        let mut sender = Sender::builder(Profile::Simple)
            .listen_addr(loopback_any())
            .flow_id(flow_id)
            .connect()
            .unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut receiver = Receiver::builder(Profile::Simple)
            .peer_addr(sender_addr)
            .flow_id(flow_id)
            .bind()
            .unwrap();

        receiver.send_feedback().unwrap().unwrap();
        let mut feedback_buf = [0u8; 1500];
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            sender
                .try_recv_feedback_and_retransmit(&mut feedback_buf)
                .unwrap();
            match sender.send(b"reverse-payload") {
                Ok(length) => {
                    assert_eq!(length, 15);
                    break;
                }
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotConnected => {}
                Err(error) => panic!("reverse Simple send failed: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "timed out discovering the Simple receiver caller"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let mut buf = [0; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"reverse-payload");
    }

    #[test]
    fn ipv6_urls_select_ipv6_local_sockets_for_both_profiles() {
        for profile in [Profile::Simple, Profile::Main] {
            let mut receiver = Receiver::builder(profile)
                .listen_url("rist://@[::1]:0")
                .unwrap()
                .bind()
                .unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            assert!(receiver_addr.is_ipv6());

            let url = format!("rist://[::1]:{}", receiver_addr.port());
            let mut sender = Sender::builder(profile)
                .peer_url(&url)
                .unwrap()
                .connect()
                .unwrap();
            assert!(sender.local_addr().unwrap().is_ipv6());

            sender.send(b"ipv6-builder").unwrap();
            let mut buf = [0u8; 1500];
            let payload = recv_eventually(&mut receiver, &mut buf);
            assert_eq!(payload.payload, b"ipv6-builder");
        }
    }

    #[test]
    fn multicast_urls_round_trip_ipv4_asm_for_both_profiles() {
        for profile in [Profile::Simple, Profile::Main] {
            let port = next_even_port_pair();
            let group = Ipv4Addr::new(239, 254, (port >> 8) as u8, port as u8);
            let listener_url = format!("rist://@{group}:{port}?miface={}", loopback_miface());
            let mut receiver = Receiver::builder(profile)
                .listen_url(&listener_url)
                .unwrap()
                .bind()
                .unwrap();

            let local_port = next_even_port_pair();
            let sender_url = format!(
                "rist://{group}:{port}?miface={}&ttl=1&local-port={local_port}",
                loopback_miface()
            );
            let mut sender = Sender::builder(profile)
                .peer_url(&sender_url)
                .unwrap()
                .connect()
                .unwrap();
            assert_eq!(sender.local_addr().unwrap().port(), local_port);

            for _ in 0..5 {
                sender.send(b"ipv4-asm").unwrap();
                thread::sleep(Duration::from_millis(10));
            }
            let mut buf = [0u8; 1500];
            let payload = recv_eventually(&mut receiver, &mut buf);
            assert_eq!(payload.payload, b"ipv4-asm");
        }
    }

    #[test]
    fn multicast_urls_round_trip_ipv4_ssm() {
        let port = next_even_port_pair();
        let group = Ipv4Addr::new(232, 254, (port >> 8) as u8, port as u8);
        let listener_url = format!("rist://@{group}:{port}?miface=127.0.0.1&source=127.0.0.1");
        let mut receiver = Receiver::builder(Profile::Main)
            .listen_url(&listener_url)
            .unwrap()
            .bind()
            .unwrap();
        let sender_url = format!("rist://{group}:{port}?miface=127.0.0.1&ttl=1");
        let mut sender = Sender::builder(Profile::Main)
            .peer_url(&sender_url)
            .unwrap()
            .connect()
            .unwrap();

        sender.send(b"ipv4-ssm").unwrap();
        let mut buf = [0u8; 1500];
        let payload = recv_eventually(&mut receiver, &mut buf);
        assert_eq!(payload.payload, b"ipv4-ssm");
    }

    #[cfg(unix)]
    #[test]
    fn multicast_urls_round_trip_ipv6_asm_for_both_profiles() {
        for profile in [Profile::Simple, Profile::Main] {
            let port = next_even_port_pair();
            let group = "ff02::114".parse::<Ipv6Addr>().unwrap();
            let listener_url = format!("rist://@[{group}]:{port}?miface={}", loopback_miface());
            let mut receiver = Receiver::builder(profile)
                .listen_url(&listener_url)
                .unwrap()
                .bind()
                .unwrap();
            let sender_url = format!("rist://[{group}]:{port}?miface={}&ttl=1", loopback_miface());
            let mut sender = Sender::builder(profile)
                .peer_url(&sender_url)
                .unwrap()
                .connect()
                .unwrap();

            for _ in 0..5 {
                sender.send(b"ipv6-asm").unwrap();
                thread::sleep(Duration::from_millis(10));
            }
            let mut buf = [0u8; 1500];
            let payload = recv_eventually(&mut receiver, &mut buf);
            assert_eq!(payload.payload, b"ipv6-asm");
        }
    }

    #[test]
    fn multicast_builders_reject_invalid_role_and_option_combinations() {
        assert!(matches!(
            Sender::builder(Profile::Main)
                .peer_url("rist://127.0.0.1:9000?ttl=1")
                .unwrap()
                .connect(),
            Err(Error::InvalidMulticastConfig(_))
        ));
        assert!(matches!(
            Receiver::builder(Profile::Main).listen_url("rist://@127.0.0.1:9000?source=127.0.0.1"),
            Err(Error::InvalidMulticastConfig(_))
        ));
        assert!(matches!(
            Receiver::builder(Profile::Main).peer_url("rist://239.0.0.1:9000"),
            Err(Error::InvalidMulticastConfig(_))
        ));
    }

    #[test]
    fn local_port_urls_bind_sender_and_receiver_callers_for_both_profiles() {
        for profile in [Profile::Simple, Profile::Main] {
            let mut receiver = Receiver::builder(profile).bind().unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let sender_port = next_even_port_pair();
            let sender_url = format!(
                "rist://127.0.0.1:{}?local-port={sender_port}",
                receiver_addr.port()
            );
            let mut sender = Sender::builder(profile)
                .peer_url(&sender_url)
                .unwrap()
                .connect()
                .unwrap();
            assert_eq!(sender.local_addr().unwrap().port(), sender_port);
            sender.send(b"sender-local-port").unwrap();
            let mut buf = [0u8; 1500];
            assert_eq!(
                recv_eventually(&mut receiver, &mut buf).payload,
                b"sender-local-port"
            );

            let mut listener = Sender::builder(profile)
                .listen_addr(loopback_any())
                .connect()
                .unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let caller_port = next_even_port_pair();
            let caller_url = format!(
                "rist://127.0.0.1:{}?local-port={caller_port}",
                listener_addr.port()
            );
            let mut caller = Receiver::builder(profile)
                .peer_url(&caller_url)
                .unwrap()
                .bind()
                .unwrap();
            assert_eq!(caller.local_addr().unwrap().port(), caller_port);
            caller.send_feedback().unwrap().unwrap();

            let mut control = [0u8; 1500];
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                listener
                    .try_recv_feedback_and_retransmit(&mut control)
                    .unwrap();
                match listener.send(b"receiver-local-port") {
                    Ok(_) => break,
                    Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotConnected => {}
                    Err(error) => panic!("listener send failed: {error}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out discovering the receiver caller"
                );
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                recv_eventually(&mut caller, &mut buf).payload,
                b"receiver-local-port"
            );
        }
    }

    #[test]
    fn builders_reject_mixed_ip_address_families() {
        let ipv4 = SocketAddr::from(([127, 0, 0, 1], 0));
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000);

        for profile in [Profile::Simple, Profile::Main] {
            let error = match Sender::builder(profile)
                .local_addr(ipv4)
                .peer_addr(ipv6)
                .connect()
            {
                Ok(_) => panic!("mixed-family sender unexpectedly connected"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
            ));

            let error = match Receiver::builder(profile)
                .local_addr(ipv4)
                .peer_addr(ipv6)
                .bind()
            {
                Ok(_) => panic!("mixed-family receiver unexpectedly connected"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
            ));
        }

        let error = match MultiSender::builder(Profile::Main)
            .peer_addr(SocketAddr::from(([127, 0, 0, 1], 9000)), 1)
            .peer_addr(ipv6, 1)
            .connect()
        {
            Ok(_) => panic!("mixed-family multipath sender unexpectedly connected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
        ));
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
    fn advanced_profile_reports_that_it_is_not_implemented() {
        let sender_result = Sender::builder(Profile::Advanced)
            .peer_addr("127.0.0.1:9000".parse().unwrap())
            .connect();
        let sender_error = match sender_result {
            Err(error) => error,
            Ok(_) => panic!("Advanced sender unexpectedly connected"),
        };
        assert!(matches!(
            sender_error,
            Error::UnsupportedProfile(Profile::Advanced)
        ));

        let receiver_error = match Receiver::builder(Profile::Advanced).bind() {
            Err(error) => error,
            Ok(_) => panic!("Advanced receiver unexpectedly bound"),
        };
        assert!(matches!(
            receiver_error,
            Error::UnsupportedProfile(Profile::Advanced)
        ));
    }

    #[test]
    fn unsupported_url_options_fail_explicitly() {
        let sender_error = Sender::builder(Profile::Main)
            .peer_url("rist://127.0.0.1:9000?timing-mode=arrival")
            .err()
            .expect("unsupported sender option must fail");
        assert!(matches!(
            sender_error,
            Error::UnsupportedUrlOption(option) if option == "timing-mode"
        ));

        let receiver_error = Receiver::builder(Profile::Main)
            .listen_url("rist://@:9000?miface=127.0.0.1")
            .err()
            .expect("unsupported receiver option must fail");
        assert!(matches!(
            receiver_error,
            Error::UnsupportedUrlOption(option) if option == "miface"
        ));
    }

    #[test]
    fn url_profile_must_match_the_pure_builder_profile() {
        let error = Sender::builder(Profile::Main)
            .peer_url("rist://127.0.0.1:9000?profile=simple")
            .err()
            .expect("mismatched profile must fail");
        assert!(matches!(
            error,
            Error::UrlProfileMismatch {
                builder: Profile::Main,
                url: Profile::Simple,
            }
        ));
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
    fn main_receiver_caller_round_trip_with_url_srp() {
        let flow_id = 0x1122_3344;
        let mut sender = Sender::builder(Profile::Main)
            .listen_url("rist://@:0?username=rist&password=reverse")
            .unwrap()
            .flow_id(flow_id)
            .connect()
            .unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let url = format!(
            "rist://127.0.0.1:{}?username=rist&password=reverse",
            sender_addr.port()
        );
        let mut receiver = Receiver::builder(Profile::Main)
            .peer_url(&url)
            .unwrap()
            .flow_id(flow_id)
            .bind()
            .unwrap();

        assert!(sender.send(b"too-early").is_err());
        receiver.start_srp_authentication().unwrap();
        let mut sender_buf = [0u8; 1500];
        let mut receiver_buf = [0u8; 1500];
        drive_srp_authentication(
            &mut sender,
            &mut receiver,
            &mut sender_buf,
            &mut receiver_buf,
        );

        assert_eq!(sender.send(b"reverse-main").unwrap(), 12);
        let payload = recv_eventually(&mut receiver, &mut receiver_buf);
        assert_eq!(payload.payload, b"reverse-main");
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
