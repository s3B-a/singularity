use super::crypto::{CryptoState, EncryptionLevel};
use super::error::{Error, ErrorCode, Result};
use super::frame::Frame;
use super::packet::{Packet, PacketHeader, PacketType, PacketNumberSpace};
use super::stream::{Stream, StreamId};
use super::recovery::RecoveryManager;
use super::{Config, ConnectionId, ConnectionState, Role, TransportParams};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::net::http::compression::{CompressionAlgorithm};
use crate::net::udp::UdpSocket;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP3_CONNECTION_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_CONNECTION_BLOB_V1";
const HTTP3_CONNECTION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_CONNECTION_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp3ConnectionBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub timestamp_unix_secs: u64,
    pub version: u16,
}

impl SecureHttp3ConnectionBlobMeta {
    pub fn new(algorithm: CompressionAlgorithm) -> Result<Self> {
        let timestamp_unix_secs = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
            Error::Crypto(format!("Time error: {}", e))
        })?.as_secs();

        Ok(Self {
            algorithm,
            timestamp_unix_secs,
            version: 1,
        })
    }

    fn to_string(&self) -> String {
        format!(
            "algorithm={},timestamp={},version={}",
            self.algorithm_name(),
            self.timestamp_unix_secs,
            self.version
        )
    }

    fn from_string(s: &str) -> Result<Self> {
        let mut algorithm = None;
        let mut timestamp_unix_secs = 0u64;
        let mut version = 0u16;
        for pair in s.split(',') {
            let (key, value) = pair.split_once('=').ok_or_else(|| {
                Error::Crypto("Invalid metadata format".to_string())
            })?;

            match key.trim() {
                "algorithm" => {
                    algorithm = Some(parse_compression_algorithm(value.trim())?);
                }
                "timestamp" => {
                    timestamp_unix_secs = value.trim().parse().map_err(|_| {
                        Error::Crypto("Invalid timestamp".to_string())
                    })?;
                }
                "version" => {
                    version = value.trim().parse().map_err(|_| {
                        Error::Crypto("Invalid version".to_string())
                    })?;
                }
                _ => {}
            }
        }

        let algorithm = algorithm.ok_or_else(|| {
            Error::Crypto("Missing algorithm".to_string())
        })?;

        Ok(Self {
            algorithm,
            timestamp_unix_secs,
            version,
        })
    }

    fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            CompressionAlgorithm::Identity => "identity",
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "brotli",
            CompressionAlgorithm::Zstd => "zstd",
        }
    }
}

pub fn select_secure_connection_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let algorithms = [
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Brotli,
        CompressionAlgorithm::Gzip,
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Identity,
    ];

    for alg in &algorithms {
        let name = match alg {
            CompressionAlgorithm::Identity => "identity",
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
        };
        if accept_encoding.contains(name) {
            return *alg;
        }
    }

    CompressionAlgorithm::Identity
}

fn parse_compression_algorithm(s: &str) -> Result<CompressionAlgorithm> {
    match s {
        "identity" => Ok(CompressionAlgorithm::Identity),
        "gzip" => Ok(CompressionAlgorithm::Gzip),
        "deflate" => Ok(CompressionAlgorithm::Deflate),
        "brotli" => Ok(CompressionAlgorithm::Brotli),
        "zstd" => Ok(CompressionAlgorithm::Zstd),
        _ => Err(Error::Crypto("Unknown compression algorithm".to_string())),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub smoothed_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub cwnd: u64,
    pub streams_opened: usize,
}

pub struct Http3Connection {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    role: Role,
    state: ConnectionState,
    config: Config,
    scid: ConnectionId,
    dcid: ConnectionId,
    odcid: Option<ConnectionId>,
    pub streams: HashMap<StreamId, Stream>,
    next_client_stream_id: StreamId,
    next_server_stream_id: StreamId,
    crypto: CryptoState,
    recovery: RecoveryManager,
    send_queue: VecDeque<Packet>,
    control_stream_id: Option<StreamId>,
    qpack_encoder_stream_id: Option<StreamId>,
    qpack_decoder_stream_id: Option<StreamId>,
    peer_settings: HashMap<u64, u64>,
    local_settings: HashMap<u64, u64>,
    pending_acks: HashMap<PacketNumberSpace, Vec<u64>>,
    next_packet_number: HashMap<PacketNumberSpace, u64>,
    last_ack_sent: HashMap<PacketNumberSpace, Instant>,
    close_reason: Option<(ErrorCode, Vec<u8>)>,
    established_time: Option<Instant>,
    idle_timeout: Duration,
    last_activity: Instant,
    peer_transport_params: Option<TransportParams>,
    max_data: u64,
    data_sent: u64,
    max_data_recieved: u64,
    data_recieved: u64,
}

impl Http3Connection {
    pub fn new_client(socket: UdpSocket, peer_addr: SocketAddr, config: Config) -> Result<Self> {
        let scid = ConnectionId::generate()?;
        let dcid = ConnectionId::generate()?;
        let mut crypto = CryptoState::new(true);
        crypto.derive_initial_keys(dcid.as_bytes())?;

        let mut next_packet_number = HashMap::new();
        next_packet_number.insert(PacketNumberSpace::Initial, 0);
        next_packet_number.insert(PacketNumberSpace::Handshake, 0);
        next_packet_number.insert(PacketNumberSpace::ApplicationData, 0);

        let mut pending_acks = HashMap::new();
        pending_acks.insert(PacketNumberSpace::Initial, Vec::new());
        pending_acks.insert(PacketNumberSpace::Handshake, Vec::new());
        pending_acks.insert(PacketNumberSpace::ApplicationData, Vec::new());

        let mut last_ack_sent = HashMap::new();
        let now = Instant::now();
        last_ack_sent.insert(PacketNumberSpace::Initial, now);
        last_ack_sent.insert(PacketNumberSpace::Handshake, now);
        last_ack_sent.insert(PacketNumberSpace::ApplicationData, now);

        Ok(Self {
            socket,
            peer_addr,
            role: Role::Client,
            state: ConnectionState::Handshake,
            config: config.clone(),
            scid,
            dcid,
            odcid: None,
            streams: HashMap::new(),
            next_client_stream_id: 0,
            next_server_stream_id: 1,
            crypto,
            recovery: RecoveryManager::new(MAX_DATAGRAM_SIZE),
            send_queue: VecDeque::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            peer_settings: HashMap::new(),
            local_settings: HashMap::new(),
            pending_acks,
            next_packet_number,
            last_ack_sent,
            close_reason: None,
            established_time: None,
            idle_timeout: config.max_idle_timeout,
            last_activity: Instant::now(),
            peer_transport_params: None,
            max_data: config.initial_max_data,
            data_sent: 0,
            max_data_recieved: config.initial_max_data,
            data_recieved: 0,
        })
    }

    pub fn new_server(socket: UdpSocket, peer_addr: SocketAddr, scid: ConnectionId, dcid: ConnectionId, config: Config) -> Result<Self> {
        let mut crypto = CryptoState::new(false);
        crypto.derive_initial_keys(dcid.as_bytes())?;

        let mut next_packet_number = HashMap::new();
        next_packet_number.insert(PacketNumberSpace::Initial, 0);
        next_packet_number.insert(PacketNumberSpace::Handshake, 0);
        next_packet_number.insert(PacketNumberSpace::ApplicationData, 0);

        let mut pending_acks = HashMap::new();
        pending_acks.insert(PacketNumberSpace::Initial, Vec::new());
        pending_acks.insert(PacketNumberSpace::Handshake, Vec::new());
        pending_acks.insert(PacketNumberSpace::ApplicationData, Vec::new());

        let mut last_ack_sent = HashMap::new();
        let now = Instant::now();
        last_ack_sent.insert(PacketNumberSpace::Initial, now);
        last_ack_sent.insert(PacketNumberSpace::Handshake, now);
        last_ack_sent.insert(PacketNumberSpace::ApplicationData, now);

        Ok(Self {
            socket,
            peer_addr,
            role: Role::Server,
            state: ConnectionState::Handshake,
            config: config.clone(),
            scid,
            dcid,
            odcid: None,
            streams: HashMap::new(),
            next_client_stream_id: 0,
            next_server_stream_id: 1,
            crypto,
            recovery: RecoveryManager::new(MAX_DATAGRAM_SIZE),
            send_queue: VecDeque::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            peer_settings: HashMap::new(),
            local_settings: HashMap::new(),
            pending_acks,
            next_packet_number,
            last_ack_sent,
            close_reason: None,
            established_time: None,
            idle_timeout: config.max_idle_timeout,
            last_activity: Instant::now(),
            peer_transport_params: None,
            max_data: config.initial_max_data,
            data_sent: 0,
            max_data_recieved: config.initial_max_data,
            data_recieved: 0,
        })
    }

    pub fn connect(&mut self) -> Result<()> {
        if self.role != Role::Client {
            return Err(Error::InvalidOperation(
                "Only client can initiate connection".to_string(),
            ));
        }

        let crypto_data = self.build_client_hello()?;
        self.send_crypto(PacketNumberSpace::Initial, crypto_data)?;
        
        Ok(())
    }

    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.dcid.as_bytes());
        payload.extend_from_slice(self.scid.as_bytes());
        
        Ok(payload)
    }

    pub fn recv(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        match self.socket.recv_from(&mut buffer) {
            Ok((size, addr)) => {
                if addr != self.peer_addr {
                    return Err(Error::InvalidOperation(
                        "Packet from unexpected peer".to_string(),
                    ));
                }

                buffer.truncate(size);
                self.process_datagram(&buffer)?;
                self.last_activity = Instant::now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(Error::WouldBlock);
            }
            Err(e) => return Err(Error::Io(e)),
        }

        Ok(())
    }

    fn process_datagram(&mut self, data: &[u8]) -> Result<()> {
        let packet = Packet::parse(data)?;
        let level = EncryptionLevel::from_packet_type(packet.header.packet_type);
        let decrypted = self.crypto.decrypt(level, packet.header.packet_number, &packet.payload, &[])?;
        let mut offset = 0;
        while offset < decrypted.len() {
            let (frame, consumed) = Frame::parse(&decrypted[offset..])?;
            offset += consumed;
            self.process_frame(&packet.header, frame)?;
        }

        let pn_space = packet.packet_number_space();
        self.pending_acks.get_mut(&pn_space).unwrap().push(packet.header.packet_number);

        Ok(())
    }

    fn process_frame(&mut self, header: &PacketHeader, frame: Frame) -> Result<()> {
        match frame {
            Frame::Crypto { offset, data } => {
                self.handle_crypto_frame(data)?;
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                self.handle_stream_frame(stream_id, offset, data, fin)?;
            }
            Frame::Ack {
                largest_ack,
                ack_delay,
                ranges,
                ..
            } => {
                self.handle_ack_frame(header, largest_ack, ack_delay, ranges)?;
            }
            Frame::ConnectionClose {
                error_code,
                reason,
                ..
            } => {
                self.handle_connection_close(error_code, reason)?;
            }
            Frame::MaxData { max } => {
                self.max_data = max;
            }
            Frame::MaxStreamData { stream_id, max } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.update_send_max_offset(max)?;
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                ..
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.handle_reset(error_code)?;
                }
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.handle_stop_sending(error_code)?;
                }
            }
            Frame::HandshakeDone => {
                if self.role == Role::Client {
                    self.on_handshake_complete()?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn send(&mut self) -> Result<()> {
        self.generate_acks()?;
        while let Some(packet) = self.send_queue.pop_front() {
            let data = packet.encode()?;
            self.socket.send_to(&data, self.peer_addr)?;
            let pn_space = packet.packet_number_space();
            self.recovery.on_packet_sent(pn_space, packet.header.packet_number, data.len(), packet.is_ack_eliciting());
        }

        Ok(())
    }

    pub fn crypto_mut(&mut self) -> &mut CryptoState {
        &mut self.crypto
    }

    pub fn get_pending_crypto(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut pending = Vec::new();
        for pn_space in &[PacketNumberSpace::Initial, PacketNumberSpace::Handshake] {
            if let Some(frame) = self.crypto.take_pending_frame(*pn_space) {
                if let Frame::Crypto { offset, data } = frame {
                    pending.push((offset, data));
                }
            }
        }

        pending
    }

    pub fn send_crypto(&mut self, pn_space: PacketNumberSpace, data: Vec<u8>) -> Result<()> {
        let frame = Frame::Crypto { offset: 0, data };

        self.send_frame(pn_space, frame)
    }

    pub fn on_handshake_keys_ready(&mut self) -> Result<()> {
        self.state = ConnectionState::Handshake;
        self.initialize_http3()?;
        Ok(())
    }

    pub fn on_application_keys_ready(&mut self) -> Result<()> {
        self.state = ConnectionState::Active;
        self.initialize_http3()?;
        Ok(())
    }

    pub fn update_keys(&mut self) -> Result<()> {
        self.crypto.update_application_keys()
    }

    fn handle_crypto_frame(&mut self, data: Vec<u8>) -> Result<()> {
        self.crypto.handle_crypto_data(&data)?;
        if self.state == ConnectionState::Handshake && self.crypto.is_handshake_complete() {
            self.on_handshake_complete()?;
        }

        Ok(())
    }

    fn handle_stream_frame(&mut self, stream_id: StreamId, offset: u64, data: Vec<u8>, fin: bool) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            let max_send = self.config.initial_max_stream_data_bidi_remote;
            let max_recv = self.config.initial_max_stream_data_bidi_local;
            let stream = Stream::new(stream_id, max_send, max_recv);
            self.streams.insert(stream_id, stream);
        }
        
        let stream = self.streams.get_mut(&stream_id).unwrap();
        stream.process_frame(offset, data, fin)?;
        self.data_recieved += offset;
        
        Ok(())
    }
    
    fn handle_ack_frame(&mut self, header: &PacketHeader, largest_ack: u64, ack_delay: u64, ranges: Vec<super::frame::AckRange>) -> Result<()> {
        let pn_space = PacketNumberSpace::from_packet_type(header.packet_type);
        let mut acked_ranges = Vec::new();
        let mut current = largest_ack;
        acked_ranges.push((current, current));
        for range in ranges {
            current -= range.gap + 2;
            let end = current;
            current -= range.len;
            acked_ranges.push((current, end));
        }
        
        let delay = Duration::from_micros(ack_delay * (1 << self.config.ack_delay_exponent));
        self.recovery.on_ack_received(
            pn_space,
            largest_ack,
            delay,
            acked_ranges,
            Instant::now(),
        )?;

        Ok(())
    }
    
    fn handle_connection_close(&mut self, error_code: ErrorCode, reason: Vec<u8>) -> Result<()> {
        self.state = ConnectionState::Draining;
        self.close_reason = Some((error_code, reason));
        
        Ok(())
    }
    
    fn on_handshake_complete(&mut self) -> Result<()> {
        self.state = ConnectionState::Active;
        self.established_time = Some(Instant::now());
        self.crypto.discard_keys(EncryptionLevel::Initial);
        if self.role == Role::Server {
            let frame = Frame::HandshakeDone;
            self.send_frame(PacketNumberSpace::ApplicationData, frame)?;
        }
        
        self.initialize_http3()?;
        
        Ok(())
    }
    
    fn initialize_http3(&mut self) -> Result<()> {
        let control_stream_id = self.create_stream()?;
        self.control_stream_id = Some(control_stream_id);
        let encoder_stream_id = self.create_stream()?;
        let decoder_stream_id = self.create_stream()?;
        self.qpack_encoder_stream_id = Some(encoder_stream_id);
        self.qpack_decoder_stream_id = Some(decoder_stream_id);
        
        self.send_http3_settings()?;
        
        Ok(())
    }

    fn send_http3_settings(&mut self) -> Result<()> {
        let settings: Vec<(u64, u64)> = self.local_settings.iter().map(|(&k, &v)| (k, v)).collect();
        let frame = Frame::Settings { settings };
        self.send_frame(PacketNumberSpace::ApplicationData, frame)?;

        Ok(())
    }
    
    fn send_frame(&mut self, pn_space: PacketNumberSpace, frame: Frame) -> Result<()> {
        let mut payload = Vec::new();
        frame.encode(&mut payload)?;
        let level = match pn_space {
            PacketNumberSpace::Initial => EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => EncryptionLevel::Handshake,
            PacketNumberSpace::ApplicationData => EncryptionLevel::Application,
        };
        
        let packet_number = self.next_packet_number.get_mut(&pn_space).unwrap();
        let pn = *packet_number;
        *packet_number += 1;
        
        let encrypted = self.crypto.encrypt(level, pn, &payload, &[])?;
        let packet_type = match pn_space {
            PacketNumberSpace::Initial => PacketType::Initial,
            PacketNumberSpace::Handshake => PacketType::Handshake,
            PacketNumberSpace::ApplicationData => PacketType::Short,
        };
        
        let packet = if packet_type == PacketType::Short {
            Packet::short(self.dcid.clone(), pn, false, encrypted)
        } else {
            let header = PacketHeader::new(
                packet_type,
                super::HTTP3_VERSION,
                self.dcid.clone(),
                self.scid.clone(),
                pn,
            );
            Packet::new(header, encrypted)
        };
        
        self.send_queue.push_back(packet);
        
        Ok(())
    }
    
    fn send_stream_data(&mut self, stream_id: StreamId) -> Result<()> {
        loop {
            let frame = {
                let stream = self.streams.get_mut(&stream_id).ok_or(Error::StreamNotFound)?;
                if !stream.has_data_to_send() {
                    break;
                }

                let max_data = (self.max_data - self.data_sent) as usize;
                if max_data == 0 {
                    break;
                }

                stream.generate_frame(max_data.min(1024))?
            };
            
            if let Some(frame) = frame {
                self.data_sent += match &frame {
                    Frame::Stream { data, .. } => data.len() as u64,
                    _ => 0,
                };
                
                self.send_frame(PacketNumberSpace::ApplicationData, frame)?;
            } else {
                break;
            }
        }
        
        Ok(())
    }
    
    fn generate_acks(&mut self) -> Result<()> {
        let now = Instant::now();
        let mut frames_to_send = Vec::new();
        for (&pn_space, acked_pns) in &mut self.pending_acks {
            if acked_pns.is_empty() {
                continue;
            }
            
            let last_sent = self.last_ack_sent.get(&pn_space).unwrap();
            if now.duration_since(*last_sent) < Duration::from_millis(25) && acked_pns.len() < 10 {
                continue;
            }
            
            acked_pns.sort_unstable();
            let largest_ack = *acked_pns.last().unwrap();
            let ranges = Vec::new();
            let frame = Frame::Ack {
                largest_ack,
                ack_delay: 0,
                ranges,
                ecn_counts: None,
            };
            
            frames_to_send.push((pn_space, frame));
            
            acked_pns.clear();
            self.last_ack_sent.insert(pn_space, now);
        }
        
        for (pn_space, frame) in frames_to_send {
            self.send_frame(pn_space, frame)?;
        }
        
        Ok(())
    }
    
    pub fn create_stream(&mut self) -> Result<StreamId> {
        if self.state != ConnectionState::Active {
            return Err(Error::InvalidOperation(
                "Connection is not active".to_string(),
            ));
        }

        let stream_id = if self.role == Role::Client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id += 4;
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id += 4;
            id
        };

        let max_send = self.config.initial_max_stream_data_bidi_local;
        let max_recv = self.config.initial_max_stream_data_bidi_remote;
        let stream = Stream::new(stream_id, max_send, max_recv);
        self.streams.insert(stream_id, stream);

        Ok(stream_id)
    }

    pub fn stream_send(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<usize> {
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::StreamNotFound)?;
        let written = if fin {
            stream.write_fin(data)?
        } else {
            stream.write(data)?
        };

        self.send_stream_data(stream_id)?;

        Ok(written)
    }

    pub fn stream_recv(&mut self, stream_id: StreamId, buffer: &mut [u8]) -> Result<usize> {
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::StreamNotFound)?;
        stream.read(buffer)
    }

    pub fn close(&mut self, error_code: ErrorCode, reason: &[u8]) -> Result<()> {
        self.state = ConnectionState::Closed;
        self.close_reason = Some((error_code, reason.to_vec()));
        let frame = Frame::ConnectionClose {
            error_code,
            frame_type: None,
            reason: reason.to_vec(),
        };

        let pn_space = if self.crypto.has_keys(EncryptionLevel::Application) {
            PacketNumberSpace::ApplicationData
        } else if self.crypto.has_keys(EncryptionLevel::Handshake) {
            PacketNumberSpace::Handshake
        } else {
            PacketNumberSpace::Initial
        };

        self.send_frame(pn_space, frame)?;

        Ok(())
    }

    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Active
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closed | ConnectionState::Draining)
    }

    pub fn stats(&self) -> ConnectionStats {
        let recovery_stats = self.recovery.stats();
        ConnectionStats {
            bytes_sent: self.data_sent,
            bytes_received: self.data_recieved,
            packets_sent: recovery_stats.bytes_sent / MAX_DATAGRAM_SIZE as u64,
            packets_received: recovery_stats.bytes_acked / MAX_DATAGRAM_SIZE as u64,
            packets_lost: recovery_stats.bytes_lost / MAX_DATAGRAM_SIZE as u64,
            smoothed_rtt: recovery_stats.smoothed_rtt,
            min_rtt: recovery_stats.min_rtt,
            cwnd: recovery_stats.cwnd,
            streams_opened: self.streams.len(),
        }
    }

    pub fn check_timeout(&mut self) -> Result<()> {
        if self.last_activity.elapsed() > self.idle_timeout {
            self.close(ErrorCode::NoError, b"Idle timeout")?;
        }
        
        Ok(())
    }
    
    pub fn stream(&self, stream_id: StreamId) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }
    
    pub fn stream_mut(&mut self, stream_id: StreamId) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }
}

pub fn encode_secure_http3_connection(conn: &Http3Connection, algorithm: CompressionAlgorithm) -> Result<Vec<u8>> {
    let meta = SecureHttp3ConnectionBlobMeta::new(algorithm)?;
    let meta_str = meta.to_string();
    let meta_bytes = meta_str.as_bytes();

    let mut payload = String::new();
    payload.push_str(&format!("peer_addr={}\n", conn.peer_addr));
    payload.push_str(&format!("role={}\n", format!("{:?}", conn.role)));
    payload.push_str(&format!("state={}\n", format!("{:?}", conn.state)));
    payload.push_str(&format!("scid={}\n", pem::encode(conn.scid.as_bytes())));
    payload.push_str(&format!("dcid={}\n", pem::encode(conn.dcid.as_bytes())));
    if let Some(odcid) = &conn.odcid {
        payload.push_str(&format!("odcid={}\n", pem::encode(odcid.as_bytes())));
    }

    payload.push_str(&format!(
        "next_client_stream_id={}\n",
        conn.next_client_stream_id
    ));

    payload.push_str(&format!(
        "next_server_stream_id={}\n",
        conn.next_server_stream_id
    ));

    payload.push_str(&format!(
        "control_stream_id={}\n",
        conn.control_stream_id.unwrap_or(0)
    ));

    payload.push_str(&format!(
        "qpack_encoder_stream_id={}\n",
        conn.qpack_encoder_stream_id.unwrap_or(0)
    ));

    payload.push_str(&format!(
        "qpack_decoder_stream_id={}\n",
        conn.qpack_decoder_stream_id.unwrap_or(0)
    ));

    payload.push_str(&format!("max_data={}\n", conn.max_data));
    payload.push_str(&format!("data_sent={}\n", conn.data_sent));
    payload.push_str(&format!("max_data_recieved={}\n", conn.max_data_recieved));
    payload.push_str(&format!("data_recieved={}\n", conn.data_recieved));

    payload.push_str(&format!(
        "peer_settings_count={}\n",
        conn.peer_settings.len()
    ));

    for (k, v) in &conn.peer_settings {
        payload.push_str(&format!("peer_settings_{}={}\n", k, v));
    }

    payload.push_str(&format!(
        "local_settings_count={}\n",
        conn.local_settings.len()
    ));

    for (k, v) in &conn.local_settings {
        payload.push_str(&format!("local_settings_{}={}\n", k, v));
    }

    payload.push_str(&format!(
        "next_packet_number_initial={}\n",
        conn.next_packet_number.get(&PacketNumberSpace::Initial).copied().unwrap_or(0)
    ));
    payload.push_str(&format!(
        "next_packet_number_handshake={}\n",
        conn.next_packet_number.get(&PacketNumberSpace::Handshake).copied().unwrap_or(0)
    ));
    payload.push_str(&format!(
        "next_packet_number_appdata={}\n",
        conn.next_packet_number.get(&PacketNumberSpace::ApplicationData).copied().unwrap_or(0)
    ));

    if let Some((error_code, reason)) = &conn.close_reason {
        payload.push_str(&format!("close_error_code={}\n", format!("{:?}", error_code)));
        payload.push_str(&format!("close_reason={}\n", pem::encode(reason)));
    }

    if let Some(est_time) = conn.established_time {
        payload.push_str(&format!(
            "established_time={}\n",
            est_time.elapsed().as_secs_f64()
        ));
    }

    payload.push_str(&format!("idle_timeout_secs={}\n", conn.idle_timeout.as_secs()));
    payload.push_str(&format!(
        "idle_timeout_nanos={}\n",
        conn.idle_timeout.subsec_nanos()
    ));

    payload.push_str(&format!(
        "last_activity_elapsed_secs={}\n",
        conn.last_activity.elapsed().as_secs_f64()
    ));

    let payload_bytes = payload.as_bytes();
    let digest = sha256(payload_bytes);
    let tag = hmac_sha256(&digest, HTTP3_CONNECTION_BLOB_CONTEXT.as_bytes());
    let mut output = Vec::new();
    output.extend_from_slice(HTTP3_CONNECTION_BLOB_MAGIC.as_bytes());
    output.push(0);
    output.extend_from_slice(meta_bytes);
    output.push(0);
    output.extend_from_slice(&digest);
    output.extend_from_slice(&tag);
    output.extend_from_slice(payload_bytes);

    Ok(output)
}

pub fn decode_secure_http3_connection(data: &[u8]) -> Result<(Http3Connection, SecureHttp3ConnectionBlobMeta)> {
    let mut cursor = 0;
    let magic_end = data.iter().skip(cursor).position(|&b| b == 0).ok_or_else(|| Error::Crypto("Invalid blob: missing magic terminator".to_string()))?;

    let magic = std::str::from_utf8(&data[cursor..cursor + magic_end]).map_err(|_| {
        Error::Crypto("Invalid UTF-8 in magic".to_string())
    })?;

    if magic != HTTP3_CONNECTION_BLOB_MAGIC {
        return Err(Error::Crypto("Invalid blob magic".to_string()));
    }

    cursor += magic_end + 1;

    let meta_end = data.iter().skip(cursor).position(|&b| b == 0).ok_or_else(|| {
        Error::Crypto("Invalid blob: missing metadata terminator".to_string())
    })?;

    let meta_str = std::str::from_utf8(&data[cursor..cursor + meta_end]).map_err(|_| {
        Error::Crypto("Invalid UTF-8 in metadata".to_string())
    })?;

    let meta = SecureHttp3ConnectionBlobMeta::from_string(meta_str)?;
    cursor += meta_end + 1;
    if cursor + 64 > data.len() {
        return Err(Error::Crypto(
            "Invalid blob: insufficient data for digest+tag".to_string(),
        ));
    }

    let stored_digest = &data[cursor..cursor + 32];
    cursor += 32;
    let stored_tag = &data[cursor..cursor + 32];
    cursor += 32;

    let payload_bytes = &data[cursor..];
    let computed_digest = sha256(payload_bytes);
    let computed_tag = hmac_sha256(&computed_digest, HTTP3_CONNECTION_BLOB_CONTEXT.as_bytes());
    if !constant_time_eq(stored_digest, &computed_digest) {
        return Err(Error::Crypto("Digest mismatch in blob".to_string()));
    }

    if !constant_time_eq(stored_tag, &computed_tag) {
        return Err(Error::Crypto("Authentication tag mismatch in blob".to_string()));
    }

    let payload_str = std::str::from_utf8(payload_bytes).map_err(|_| {
        Error::Crypto("Invalid UTF-8 in payload".to_string())
    })?;

    let mut params: HashMap<String, String> = HashMap::new();
    for line in payload_str.lines() {
        if let Some((k, v)) = line.split_once('=') {
            params.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let peer_addr = params.get("peer_addr").ok_or_else(|| {
        Error::Crypto("Missing peer_addr".to_string())
    })?.parse().map_err(|_| Error::Crypto("Invalid peer_addr".to_string()))?;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::Io(e))?;
    let config = Config::default();

    let role = if params.get("role").map(|s| {
        s.contains("Client")
    }).unwrap_or(false) {
        Role::Client
    } else {
        Role::Server
    };

    let mut conn = if role == Role::Client {
        Http3Connection::new_client(socket, peer_addr, config)?
    } else {
        let _ = pem::decode(params.get("scid").ok_or_else(|| {
            Error::Crypto("Missing scid".to_string())
        })?).map_err(|_| {
            Error::Crypto("Failed to decode scid".to_string())
        })?;

        let _ = pem::decode(params.get("dcid").ok_or_else(|| {
            Error::Crypto("Missing dcid".to_string())
        })?).map_err(|_| {
            Error::Crypto("Failed to decode dcid".to_string())
        })?;

        let scid = ConnectionId::generate()?;
        let dcid = ConnectionId::generate()?;
        Http3Connection::new_server(socket, peer_addr, scid, dcid, config)?
    };

    if let Some(odcid_str) = params.get("odcid") {
        if !odcid_str.is_empty() {
            let _odcid_bytes = pem::decode(odcid_str).map_err(|_| {
                Error::Crypto("Failed to decode odcid".to_string())
            })?;

            conn.odcid = Some(ConnectionId::generate()?);
        }
    }

    if let Some(state_str) = params.get("state") {
        conn.state = parse_connection_state(state_str)?;
    }

    if let Some(next_client_id) = params.get("next_client_stream_id") {
        conn.next_client_stream_id = next_client_id.parse().unwrap_or(0);
    }

    if let Some(next_server_id) = params.get("next_server_stream_id") {
        conn.next_server_stream_id = next_server_id.parse().unwrap_or(1);
    }

    if let Some(control_id) = params.get("control_stream_id") {
        if let Ok(id) = control_id.parse::<u64>() {
            if id > 0 {
                conn.control_stream_id = Some(id);
            }
        }
    }

    if let Some(encoder_id) = params.get("qpack_encoder_stream_id") {
        if let Ok(id) = encoder_id.parse::<u64>() {
            if id > 0 {
                conn.qpack_encoder_stream_id = Some(id);
            }
        }
    }

    if let Some(decoder_id) = params.get("qpack_decoder_stream_id") {
        if let Ok(id) = decoder_id.parse::<u64>() {
            if id > 0 {
                conn.qpack_decoder_stream_id = Some(id);
            }
        }
    }

    if let Ok(val) = params.get("max_data").ok_or_else(|| {
        Error::Crypto("Missing max_data".to_string())
    })?.parse::<u64>() {
        conn.max_data = val;
    }

    if let Ok(val) = params.get("data_sent").ok_or_else(|| {
        Error::Crypto("Missing data_sent".to_string())
    })?.parse::<u64>() {
        conn.data_sent = val;
    }

    if let Ok(val) = params.get("max_data_recieved").ok_or_else(|| {
        Error::Crypto("Missing max_data_recieved".to_string())
    })?.parse::<u64>() {
        conn.max_data_recieved = val;
    }

    if let Ok(val) = params.get("data_recieved").ok_or_else(|| {
        Error::Crypto("Missing data_recieved".to_string())
    })?.parse::<u64>() {
        conn.data_recieved = val;
    }

    if let Ok(count) = params.get("peer_settings_count").unwrap_or(&"0".to_string()).parse::<usize>() {
        for i in 0..count {
            if let Some(val_str) = params.get(&format!("peer_settings_{}", i)) {
                if let Ok(val) = val_str.parse::<u64>() {
                    conn.peer_settings.insert(i as u64, val);
                }
            }
        }
    }

    if let Ok(count) = params.get("local_settings_count").unwrap_or(&"0".to_string()).parse::<usize>() {
        for i in 0..count {
            if let Some(val_str) = params.get(&format!("local_settings_{}", i)) {
                if let Ok(val) = val_str.parse::<u64>() {
                    conn.local_settings.insert(i as u64, val);
                }
            }
        }
    }

    if let Ok(val) = params.get("next_packet_number_initial").unwrap_or(&"0".to_string()).parse::<u64>() {
        conn.next_packet_number.insert(PacketNumberSpace::Initial, val);
    }

    if let Ok(val) = params.get("next_packet_number_handshake").unwrap_or(&"0".to_string()).parse::<u64>() {
        conn.next_packet_number.insert(PacketNumberSpace::Handshake, val);
    }

    if let Ok(val) = params.get("next_packet_number_appdata").unwrap_or(&"0".to_string()).parse::<u64>() {
        conn.next_packet_number.insert(PacketNumberSpace::ApplicationData, val);
    }

    if let Ok(count) = params.get("pending_acks_initial_count").unwrap_or(&"0".to_string()).parse::<usize>() {
        let mut acks = Vec::new();
        for i in 0..count {
            if let Some(val_str) = params.get(&format!("pending_acks_initial_{}", i)) {
                if let Ok(val) = val_str.parse::<u64>() {
                    acks.push(val);
                }
            }
        }

        if !acks.is_empty() {
            conn.pending_acks.insert(PacketNumberSpace::Initial, acks);
        }
    }

    if let Ok(count) = params.get("pending_acks_handshake_count").unwrap_or(&"0".to_string()).parse::<usize>() {
        let mut acks = Vec::new();
        for i in 0..count {
            if let Some(val_str) = params.get(&format!("pending_acks_handshake_{}", i)) {
                if let Ok(val) = val_str.parse::<u64>() {
                    acks.push(val);
                }
            }
        }

        if !acks.is_empty() {
            conn.pending_acks.insert(PacketNumberSpace::Handshake, acks);
        }
    }

    if let Ok(count) = params.get("pending_acks_appdata_count").unwrap_or(&"0".to_string()).parse::<usize>() {
        let mut acks = Vec::new();
        for i in 0..count {
            if let Some(val_str) = params.get(&format!("pending_acks_appdata_{}", i)) {
                if let Ok(val) = val_str.parse::<u64>() {
                    acks.push(val);
                }
            }
        }

        if !acks.is_empty() {
            conn.pending_acks
                .insert(PacketNumberSpace::ApplicationData, acks);
        }
    }

    if let Some(error_code_str) = params.get("close_error_code") {
        if let Some(reason_str) = params.get("close_reason") {
            if let Ok(reason_bytes) = pem::decode(reason_str) {
                let error_code = parse_error_code(error_code_str)?;
                conn.close_reason = Some((error_code, reason_bytes));
            }
        }
    }

    if let Ok(secs) = params.get("idle_timeout_secs").unwrap_or(&"0".to_string()).parse::<u64>() {
        if let Ok(nanos) = params.get("idle_timeout_nanos").unwrap_or(&"0".to_string()).parse::<u32>() {
            conn.idle_timeout = Duration::new(secs, nanos);
        }
    }

    Ok((conn, meta))
}

fn parse_connection_state(s: &str) -> Result<ConnectionState> {
    match s {
        s if s.contains("Handshake") => Ok(ConnectionState::Handshake),
        s if s.contains("Active") => Ok(ConnectionState::Active),
        s if s.contains("Draining") => Ok(ConnectionState::Draining),
        s if s.contains("Closed") => Ok(ConnectionState::Closed),
        _ => Err(Error::Crypto("Unknown connection state".to_string())),
    }
}

fn parse_error_code(s: &str) -> Result<ErrorCode> {
    match s {
        s if s.contains("NoError") => Ok(ErrorCode::NoError),
        s if s.contains("FrameEncodingError") => Ok(ErrorCode::FrameEncodingError),
        s if s.contains("FrameTypeError") => Ok(ErrorCode::FrameEncodingError),
        s if s.contains("StreamStateError") => Ok(ErrorCode::StreamStateError),
        s if s.contains("StreamLimitError") => Ok(ErrorCode::StreamLimitError),
        s if s.contains("AckDelayExponentError") => Ok(ErrorCode::FrameEncodingError),
        s if s.contains("MaxDataError") => Ok(ErrorCode::StreamLimitError),
        s if s.contains("MaxStreamDataError") => Ok(ErrorCode::StreamStateError),
        s if s.contains("InvariantViolation") => Ok(ErrorCode::FrameEncodingError),
        _ => {
            if s.parse::<u64>().is_ok() {
                Ok(ErrorCode::ApplicationError)
            } else {
                Err(Error::Crypto("Unknown error code".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    fn create_test_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }
    
    fn create_test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433)
    }
    
    #[test]
    fn test_connection_creation() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        
        let conn = Http3Connection::new_client(socket, addr, config);
        assert!(conn.is_ok());
        
        let conn = conn.unwrap();
        assert_eq!(conn.role, Role::Client);
        assert_eq!(conn.state, ConnectionState::Handshake);
    }
    
    #[test]
    fn test_stream_creation() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active; // Simulate established
        
        let stream_id = conn.create_stream().unwrap();
        assert_eq!(stream_id, 0);
        assert!(conn.streams.contains_key(&stream_id));
        
        let stream_id2 = conn.create_stream().unwrap();
        assert_eq!(stream_id2, 4);
    }
    
    #[test]
    fn test_connection_stats() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        
        let conn = Http3Connection::new_client(socket, addr, config).unwrap();
        let stats = conn.stats();
        
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.streams_opened, 0);
    }
    
    #[test]
    fn test_connection_close() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;
        
        conn.close(ErrorCode::NoError, b"Normal close").unwrap();
        assert_eq!(conn.state, ConnectionState::Closed);
        assert!(conn.close_reason.is_some());
    }
    
    #[test]
    fn test_flow_control() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;
        
        let initial_max = conn.max_data;
        assert!(initial_max > 0);
        
        conn.data_sent = initial_max;
        assert_eq!(conn.max_data - conn.data_sent, 0);
    }

    #[test]
    fn test_secure_blob_roundtrip() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;
        conn.data_sent = 42;
        conn.data_recieved = 84;

        let encoded = encode_secure_http3_connection(&conn, CompressionAlgorithm::Identity).unwrap();
        let (decoded_conn, meta) = decode_secure_http3_connection(&encoded).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_conn.data_sent, conn.data_sent);
        assert_eq!(decoded_conn.data_recieved, conn.data_recieved);
    }

    #[test]
    fn test_secure_blob_tamper_detection() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let conn = Http3Connection::new_client(socket, addr, config).unwrap();
        let mut encoded = encode_secure_http3_connection(&conn, CompressionAlgorithm::Identity).unwrap();

        // Tamper with the payload
        if encoded.len() > 100 {
            encoded[100] ^= 0xFF;
        }

        let result = decode_secure_http3_connection(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_blob_metadata_preservation() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let conn = Http3Connection::new_client(socket, addr, config).unwrap();

        for alg in &[
            CompressionAlgorithm::Identity,
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Deflate,
        ] {
            let encoded = encode_secure_http3_connection(&conn, *alg).unwrap();
            let (_, meta) = decode_secure_http3_connection(&encoded).unwrap();
            assert_eq!(meta.algorithm, *alg);
        }
    }
}