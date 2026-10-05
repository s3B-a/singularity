use super::crypto::{CryptoState, EncryptionLevel};
use super::error::{Error, ErrorCode, Result};
use super::frame::Frame;
use super::h3_frame::{self, H3_STREAM_TYPE_CONTROL, H3_STREAM_TYPE_QPACK_DECODER, H3_STREAM_TYPE_QPACK_ENCODER};
use super::packet::{Packet, PacketHeader, PacketNumber, PacketType, PacketNumberSpace};
use super::qpack::{QpackDecoder, QpackEncoder};
use super::stream::{Stream, StreamId, StreamType};
use super::recovery::RecoveryManager;
use super::{decode_varint, Config, ConnectionId, ConnectionState, Role, TransportParams};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniStreamKind {
    Control,
    QpackEncoder,
    QpackDecoder,
    Unknown,
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
    next_client_uni_stream_id: StreamId,
    next_server_uni_stream_id: StreamId,
    crypto: CryptoState,
    recovery: RecoveryManager,
    send_queue: VecDeque<Packet>,
    control_stream_id: Option<StreamId>,
    qpack_encoder_stream_id: Option<StreamId>,
    qpack_decoder_stream_id: Option<StreamId>,
    peer_control_stream_id: Option<StreamId>,
    peer_qpack_encoder_stream_id: Option<StreamId>,
    peer_qpack_decoder_stream_id: Option<StreamId>,
    uni_stream_kind: HashMap<StreamId, UniStreamKind>,
    uni_stream_pending: HashMap<StreamId, Vec<u8>>,
    qpack_encoder: QpackEncoder,
    qpack_decoder: QpackDecoder,
    peer_settings: HashMap<u64, u64>,
    local_settings: HashMap<u64, u64>,
    pending_acks: HashMap<PacketNumberSpace, Vec<u64>>,
    next_packet_number: HashMap<PacketNumberSpace, u64>,
    last_ack_sent: HashMap<PacketNumberSpace, Instant>,
    largest_pn_seen: HashMap<PacketNumberSpace, u64>,
    close_reason: Option<(ErrorCode, Vec<u8>)>,
    established_time: Option<Instant>,
    idle_timeout: Duration,
    last_activity: Instant,
    peer_transport_params: Option<TransportParams>,
    max_data: u64,
    data_sent: u64,
    max_data_recieved: u64,
    data_recieved: u64,
    address_validated: bool,
    bytes_received_before_validation: usize,
    bytes_sent_before_validation: usize,
    pending_retry: Option<(Vec<u8>, ConnectionId)>,
    outgoing_initial_token: Option<Vec<u8>>,
    peer_connection_ids: HashMap<u64, (ConnectionId, [u8; 16])>,
    last_path_response: Option<[u8; 8]>,
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
            next_client_uni_stream_id: 2,
            next_server_uni_stream_id: 3,
            crypto,
            recovery: RecoveryManager::new(MAX_DATAGRAM_SIZE),
            send_queue: VecDeque::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            peer_control_stream_id: None,
            peer_qpack_encoder_stream_id: None,
            peer_qpack_decoder_stream_id: None,
            uni_stream_kind: HashMap::new(),
            uni_stream_pending: HashMap::new(),
            qpack_encoder: QpackEncoder::new(0),
            qpack_decoder: QpackDecoder::new(config.qpack_max_table_capacity as usize),
            peer_settings: HashMap::new(),
            local_settings: HashMap::new(),
            pending_acks,
            next_packet_number,
            last_ack_sent,
            largest_pn_seen: HashMap::new(),
            close_reason: None,
            established_time: None,
            idle_timeout: config.max_idle_timeout,
            last_activity: Instant::now(),
            peer_transport_params: None,
            max_data: config.initial_max_data,
            data_sent: 0,
            max_data_recieved: config.initial_max_data,
            data_recieved: 0,
            address_validated: true,
            bytes_received_before_validation: 0,
            bytes_sent_before_validation: 0,
            pending_retry: None,
            outgoing_initial_token: None,
            peer_connection_ids: HashMap::new(),
            last_path_response: None,
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
            next_client_uni_stream_id: 2,
            next_server_uni_stream_id: 3,
            crypto,
            recovery: RecoveryManager::new(MAX_DATAGRAM_SIZE),
            send_queue: VecDeque::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            peer_control_stream_id: None,
            peer_qpack_encoder_stream_id: None,
            peer_qpack_decoder_stream_id: None,
            uni_stream_kind: HashMap::new(),
            uni_stream_pending: HashMap::new(),
            qpack_encoder: QpackEncoder::new(0),
            qpack_decoder: QpackDecoder::new(config.qpack_max_table_capacity as usize),
            peer_settings: HashMap::new(),
            local_settings: HashMap::new(),
            pending_acks,
            next_packet_number,
            last_ack_sent,
            largest_pn_seen: HashMap::new(),
            close_reason: None,
            established_time: None,
            idle_timeout: config.max_idle_timeout,
            last_activity: Instant::now(),
            peer_transport_params: None,
            max_data: config.initial_max_data,
            data_sent: 0,
            max_data_recieved: config.initial_max_data,
            data_recieved: 0,
            address_validated: false,
            bytes_received_before_validation: 0,
            bytes_sent_before_validation: 0,
            pending_retry: None,
            outgoing_initial_token: None,
            peer_connection_ids: HashMap::new(),
            last_path_response: None,
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
        if data.is_empty() {
            return Err(Error::BufferTooShort);
        }

        if self.role == Role::Server && !self.address_validated {
            self.bytes_received_before_validation += data.len();
        }

        let first = data[0];
        let (packet_type, pn_offset) = if first & 0x80 != 0 {
            if data.len() < 5 {
                return Err(Error::BufferTooShort);
            }

            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            if version == 0 {
                return Ok(());
            }

            let type_bits = (first & 0x30) >> 4;
            if PacketType::from_long_header_type(type_bits)? == PacketType::Retry {
                if self.role == Role::Client {
                    self.handle_retry_packet(data)?;
                }

                return Ok(());
            }

            let prefix = PacketHeader::parse_protected_long_prefix(data)?;
            (prefix.packet_type, prefix.pn_offset)
        } else {
            let prefix = PacketHeader::parse_protected_short_prefix(data)?;
            (PacketType::Short, prefix.pn_offset)
        };

        let level = EncryptionLevel::from_packet_type(packet_type);
        let pn_space = PacketNumberSpace::from_packet_type(packet_type);

        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > data.len() {
            return Err(Error::BufferTooShort);
        }

        let mut header_buf = data[..sample_offset].to_vec();
        let sample = &data[sample_offset..sample_offset + 16];
        let pn_len = self.crypto.unprotect_header(level, &mut header_buf, pn_offset, sample)?;

        let mut truncated_pn = 0u64;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | (header_buf[pn_offset + i] as u64);
        }

        let largest_pn = *self.largest_pn_seen.get(&pn_space).unwrap_or(&0);
        let packet_number = PacketNumber::decode(truncated_pn, pn_len, largest_pn);

        let header_len = pn_offset + pn_len;
        let payload = &data[header_len..];
        let decrypted = self.crypto.decrypt(level, packet_number, payload, &[])?;

        if self.role == Role::Server && !self.address_validated && level != EncryptionLevel::Initial {
            self.address_validated = true;
        }

        let mut offset = 0;
        while offset < decrypted.len() {
            let (frame, consumed) = Frame::parse(&decrypted[offset..])?;
            offset += consumed;
            self.process_frame(packet_type, frame)?;
        }

        self.pending_acks.get_mut(&pn_space).unwrap().push(packet_number);

        let largest_seen = self.largest_pn_seen.entry(pn_space).or_insert(0);
        if packet_number > *largest_seen {
            *largest_seen = packet_number;
        }

        self.poll_peer_uni_streams()?;

        Ok(())
    }

    fn handle_retry_packet(&mut self, data: &[u8]) -> Result<()> {
        if self.pending_retry.is_some() {
            return Ok(());
        }

        if data.len() < 16 {
            return Ok(());
        }

        let packet = match Packet::parse(data) {
            Ok(packet) => packet,
            Err(_) => return Ok(()),
        };

        if packet.payload.len() < 16 {
            return Ok(());
        }

        let (token, tag) = packet.payload.split_at(packet.payload.len() - 16);
        let header_and_token = &data[..data.len() - 16];
        let expected_tag = match super::crypto::compute_retry_integrity_tag(self.dcid.as_bytes(), header_and_token) {
            Ok(tag) => tag,
            Err(_) => return Ok(()),
        };

        if !constant_time_eq(&expected_tag, tag) {
            return Ok(());
        }

        self.pending_retry = Some((token.to_vec(), packet.header.scid.clone()));
        self.dcid = packet.header.scid;
        self.outgoing_initial_token = Some(token.to_vec());

        Ok(())
    }

    pub fn take_pending_retry(&mut self) -> Option<(Vec<u8>, ConnectionId)> {
        self.pending_retry.take()
    }

    pub fn set_initial_token(&mut self, token: Vec<u8>) {
        self.outgoing_initial_token = Some(token);
    }

    pub fn mark_address_validated(&mut self) {
        self.address_validated = true;
    }

    pub fn set_odcid(&mut self, odcid: ConnectionId) {
        self.odcid = Some(odcid);
    }

    pub fn odcid(&self) -> Option<&ConnectionId> {
        self.odcid.as_ref()
    }

    pub fn is_address_validated(&self) -> bool {
        self.address_validated
    }

    fn poll_peer_uni_streams(&mut self) -> Result<()> {
        let peer_uni_bits = if self.role == Role::Client { 0x03 } else { 0x02 };
        let candidate_ids: Vec<StreamId> = self
            .streams
            .keys()
            .copied()
            .filter(|id| id & 0x03 == peer_uni_bits)
            .collect();

        for stream_id in candidate_ids {
            self.drain_peer_uni_stream(stream_id)?;
        }

        Ok(())
    }

    fn drain_peer_uni_stream(&mut self, stream_id: StreamId) -> Result<()> {
        loop {
            let mut buf = [0u8; 512];
            let n = match self.streams.get_mut(&stream_id) {
                Some(stream) => match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => break,
                },
                None => return Ok(()),
            };

            if n == 0 {
                break;
            }

            self.uni_stream_pending.entry(stream_id).or_default().extend_from_slice(&buf[..n]);
        }

        self.process_peer_uni_stream_buffer(stream_id)
    }

    fn process_peer_uni_stream_buffer(&mut self, stream_id: StreamId) -> Result<()> {
        let kind = match self.uni_stream_kind.get(&stream_id).copied() {
            Some(kind) => kind,
            None => {
                let buf = self.uni_stream_pending.get(&stream_id).cloned().unwrap_or_default();
                let (stream_type, consumed) = match decode_varint(&buf) {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                };

                let kind = match stream_type {
                    H3_STREAM_TYPE_CONTROL => UniStreamKind::Control,
                    H3_STREAM_TYPE_QPACK_ENCODER => UniStreamKind::QpackEncoder,
                    H3_STREAM_TYPE_QPACK_DECODER => UniStreamKind::QpackDecoder,
                    _ => UniStreamKind::Unknown,
                };

                self.uni_stream_kind.insert(stream_id, kind);
                match kind {
                    UniStreamKind::Control => self.peer_control_stream_id = Some(stream_id),
                    UniStreamKind::QpackEncoder => self.peer_qpack_encoder_stream_id = Some(stream_id),
                    UniStreamKind::QpackDecoder => self.peer_qpack_decoder_stream_id = Some(stream_id),
                    UniStreamKind::Unknown => {}
                }

                if let Some(buffer) = self.uni_stream_pending.get_mut(&stream_id) {
                    buffer.drain(0..consumed);
                }

                kind
            }
        };

        match kind {
            UniStreamKind::Control => self.process_peer_control_stream(stream_id)?,
            UniStreamKind::QpackEncoder => self.process_peer_qpack_encoder_stream(stream_id)?,
            UniStreamKind::QpackDecoder => self.process_peer_qpack_decoder_stream(stream_id)?,
            UniStreamKind::Unknown => {}
        }

        Ok(())
    }

    fn process_peer_control_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let buf = self.uni_stream_pending.get(&stream_id).cloned().unwrap_or_default();
        let (frames, consumed) = h3_frame::parse_h3_frames(&buf)?;
        let mut received_settings = false;
        for (frame_type, payload) in frames {
            if frame_type == h3_frame::H3_FRAME_SETTINGS {
                let settings = h3_frame::parse_settings_payload(&payload)?;
                for (id, value) in settings {
                    self.peer_settings.insert(id, value);
                }
                received_settings = true;
            }
        }

        if consumed > 0 {
            if let Some(buffer) = self.uni_stream_pending.get_mut(&stream_id) {
                buffer.drain(0..consumed);
            }
        }

        if received_settings {
            self.apply_peer_qpack_capacity()?;
        }

        Ok(())
    }

    fn apply_peer_qpack_capacity(&mut self) -> Result<()> {
        let peer_capacity = self
            .peer_settings
            .get(&h3_frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY)
            .copied()
            .unwrap_or(0);
        let capacity = peer_capacity.min(self.config.qpack_max_table_capacity) as usize;

        self.qpack_encoder.set_capacity_and_announce(capacity)?;
        let instructions = self.qpack_encoder.drain_instructions();
        if !instructions.is_empty() {
            if let Some(stream_id) = self.qpack_encoder_stream_id {
                self.stream_send(stream_id, &instructions, false)?;
            }
        }

        Ok(())
    }

    fn process_peer_qpack_encoder_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let buf = self.uni_stream_pending.get(&stream_id).cloned().unwrap_or_default();
        if buf.is_empty() {
            return Ok(());
        }

        let consumed = self.qpack_decoder.process_encoder_instructions(&buf)?;
        if consumed > 0 {
            if let Some(buffer) = self.uni_stream_pending.get_mut(&stream_id) {
                buffer.drain(0..consumed);
            }
        }

        let decoder_instructions = self.qpack_decoder.drain_instructions();
        if !decoder_instructions.is_empty() {
            if let Some(our_decoder_stream_id) = self.qpack_decoder_stream_id {
                self.stream_send(our_decoder_stream_id, &decoder_instructions, false)?;
            }
        }

        Ok(())
    }

    fn process_peer_qpack_decoder_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let buf = self.uni_stream_pending.get(&stream_id).cloned().unwrap_or_default();
        if buf.is_empty() {
            return Ok(());
        }

        let consumed = self.qpack_encoder.process_decoder_instructions(&buf)?;
        if consumed > 0 {
            if let Some(buffer) = self.uni_stream_pending.get_mut(&stream_id) {
                buffer.drain(0..consumed);
            }
        }

        Ok(())
    }

    fn process_frame(&mut self, packet_type: PacketType, frame: Frame) -> Result<()> {
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
                self.handle_ack_frame(packet_type, largest_ack, ack_delay, ranges)?;
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
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            } => {
                self.handle_new_connection_id(sequence, retire_prior_to, connection_id, stateless_reset_token)?;
            }
            Frame::RetireConnectionId { sequence } => {
                self.peer_connection_ids.remove(&sequence);
            }
            Frame::PathChallenge { data } => {
                self.send_frame(PacketNumberSpace::ApplicationData, Frame::PathResponse { data })?;
            }
            Frame::PathResponse { data } => {
                self.last_path_response = Some(data);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_new_connection_id(&mut self, sequence: u64, retire_prior_to: u64, connection_id: ConnectionId, stateless_reset_token: [u8; 16]) -> Result<()> {
        self.peer_connection_ids.insert(sequence, (connection_id, stateless_reset_token));
        let to_retire: Vec<u64> = self.peer_connection_ids.keys().copied().filter(|&seq| seq < retire_prior_to).collect();
        for seq in to_retire {
            self.peer_connection_ids.remove(&seq);
            self.send_frame(PacketNumberSpace::ApplicationData, Frame::RetireConnectionId { sequence: seq })?;
        }

        Ok(())
    }

    pub fn peer_connection_ids(&self) -> &HashMap<u64, (ConnectionId, [u8; 16])> {
        &self.peer_connection_ids
    }

    pub fn last_path_response(&self) -> Option<[u8; 8]> {
        self.last_path_response
    }

    pub fn send(&mut self) -> Result<()> {
        self.generate_acks()?;
        while let Some(packet) = self.send_queue.pop_front() {
            let level = EncryptionLevel::from_packet_type(packet.header.packet_type);
            let (mut data, pn_offset, pn_len) = packet.encode_with_pn_info()?;

            if self.role == Role::Server && !self.address_validated {
                let would_send = self.bytes_sent_before_validation + data.len();
                if would_send > self.bytes_received_before_validation.saturating_mul(3) {
                    self.send_queue.push_front(packet);
                    break;
                }
            }

            if pn_len > 0 {
                let sample_offset = pn_offset + 4;
                if sample_offset + 16 > data.len() {
                    return Err(Error::InvalidOperation(
                        "packet too short to sample for header protection".to_string(),
                    ));
                }

                let sample = data[sample_offset..sample_offset + 16].to_vec();
                self.crypto.protect_header(level, &mut data[..pn_offset + pn_len], pn_offset, &sample)?;
            }

            self.socket.send_to(&data, self.peer_addr)?;

            if self.role == Role::Server && !self.address_validated {
                self.bytes_sent_before_validation += data.len();
            }

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
            let (max_send, max_recv) = if StreamType::from_id(stream_id).is_unidirectional() {
                let max = self.config.initial_max_stream_data_uni;
                (max, max)
            } else {
                (
                    self.config.initial_max_stream_data_bidi_remote,
                    self.config.initial_max_stream_data_bidi_local,
                )
            };

            let stream = Stream::new(stream_id, max_send, max_recv);
            self.streams.insert(stream_id, stream);
        }
        
        let stream = self.streams.get_mut(&stream_id).unwrap();
        stream.process_frame(offset, data, fin)?;
        self.data_recieved += offset;
        
        Ok(())
    }
    
    fn handle_ack_frame(&mut self, packet_type: PacketType, largest_ack: u64, ack_delay: u64, ranges: Vec<super::frame::AckRange>) -> Result<()> {
        let pn_space = PacketNumberSpace::from_packet_type(packet_type);
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
        if self.control_stream_id.is_some() {
            return Ok(());
        }

        if self.local_settings.is_empty() {
            self.local_settings.insert(
                h3_frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                self.config.qpack_max_table_capacity,
            );
            self.local_settings.insert(
                h3_frame::SETTINGS_QPACK_BLOCKED_STREAMS,
                self.config.qpack_blocked_streams,
            );
        }

        let control_stream_id = self.create_uni_stream()?;
        self.control_stream_id = Some(control_stream_id);
        self.stream_send(control_stream_id, &h3_frame::encode_stream_type(H3_STREAM_TYPE_CONTROL), false)?;

        let encoder_stream_id = self.create_uni_stream()?;
        self.qpack_encoder_stream_id = Some(encoder_stream_id);
        self.stream_send(encoder_stream_id, &h3_frame::encode_stream_type(H3_STREAM_TYPE_QPACK_ENCODER), false)?;

        let decoder_stream_id = self.create_uni_stream()?;
        self.qpack_decoder_stream_id = Some(decoder_stream_id);
        self.stream_send(decoder_stream_id, &h3_frame::encode_stream_type(H3_STREAM_TYPE_QPACK_DECODER), false)?;

        self.send_http3_settings()?;

        Ok(())
    }

    fn send_http3_settings(&mut self) -> Result<()> {
        let settings: Vec<(u64, u64)> = self.local_settings.iter().map(|(&k, &v)| (k, v)).collect();
        let frame_bytes = h3_frame::encode_settings_frame(&settings);
        let stream_id = self
            .control_stream_id
            .ok_or_else(|| Error::InvalidOperation("Control stream not created".to_string()))?;
        self.stream_send(stream_id, &frame_bytes, false)?;

        Ok(())
    }
    
    fn send_frame(&mut self, pn_space: PacketNumberSpace, frame: Frame) -> Result<()> {
        let mut payload = Vec::new();
        frame.encode(&mut payload)?;
        const MIN_PLAINTEXT_LEN: usize = 4;
        if payload.len() < MIN_PLAINTEXT_LEN {
            payload.resize(MIN_PLAINTEXT_LEN, 0);
        }

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

        let largest_acked = self.recovery.largest_acked(pn_space);

        let packet = if packet_type == PacketType::Short {
            let mut packet = Packet::short(self.dcid.clone(), pn, false, encrypted);
            packet.header.largest_acked = largest_acked;
            packet
        } else {
            let mut header = PacketHeader::new(
                packet_type,
                super::HTTP3_VERSION,
                self.dcid.clone(),
                self.scid.clone(),
                pn,
            );
            header.largest_acked = largest_acked;
            if packet_type == PacketType::Initial {
                header.token = self.outgoing_initial_token.clone();
            }
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

    pub fn create_uni_stream(&mut self) -> Result<StreamId> {
        if self.state != ConnectionState::Active {
            return Err(Error::InvalidOperation(
                "Connection is not active".to_string(),
            ));
        }

        let stream_id = if self.role == Role::Client {
            let id = self.next_client_uni_stream_id;
            self.next_client_uni_stream_id += 4;
            id
        } else {
            let id = self.next_server_uni_stream_id;
            self.next_server_uni_stream_id += 4;
            id
        };

        let max = self.config.initial_max_stream_data_uni;
        let stream = Stream::new(stream_id, max, max);
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
            return Ok(());
        }

        self.check_loss_recovery_timeout()?;

        Ok(())
    }

    fn check_loss_recovery_timeout(&mut self) -> Result<()> {
        let now = Instant::now();
        let deadline = match self.recovery.pto_deadline() {
            Some(deadline) => deadline,
            None => return Ok(()),
        };

        if now < deadline {
            return Ok(());
        }

        self.recovery.loss_detection_timeout(now)?;

        for space in self.recovery.ack_eliciting_in_flight_spaces() {
            let level = match space {
                PacketNumberSpace::Initial => EncryptionLevel::Initial,
                PacketNumberSpace::Handshake => EncryptionLevel::Handshake,
                PacketNumberSpace::ApplicationData => EncryptionLevel::Application,
            };

            if self.crypto.has_keys(level) {
                self.send_frame(space, Frame::Ping)?;
            }
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
    fn test_initialize_http3_creates_real_uni_streams_and_settings() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;

        let keys = super::super::crypto::CryptoKeys::new(vec![0u8; 16], vec![1u8; 16], vec![2u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        conn.initialize_http3().unwrap();

        assert_eq!(conn.control_stream_id, Some(2));
        assert_eq!(conn.qpack_encoder_stream_id, Some(6));
        assert_eq!(conn.qpack_decoder_stream_id, Some(10));

        let mut per_stream: HashMap<StreamId, Vec<u8>> = HashMap::new();
        for packet in &conn.send_queue {
            let level = EncryptionLevel::from_packet_type(packet.header.packet_type);
            let decrypted = conn
                .crypto
                .decrypt(level, packet.header.packet_number, &packet.payload, &[])
                .unwrap();

            let mut offset = 0;
            while offset < decrypted.len() {
                let (frame, consumed) = Frame::parse(&decrypted[offset..]).unwrap();
                offset += consumed;
                if let Frame::Stream { stream_id, data, .. } = frame {
                    per_stream.entry(stream_id).or_default().extend_from_slice(&data);
                }
            }
        }

        assert_eq!(per_stream.get(&6).unwrap(), &vec![0x02]);
        assert_eq!(per_stream.get(&10).unwrap(), &vec![0x03]);

        let control_bytes = per_stream.get(&2).unwrap();
        assert_eq!(control_bytes[0], 0x00);

        let (frames, _consumed) = h3_frame::parse_h3_frames(&control_bytes[1..]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, h3_frame::H3_FRAME_SETTINGS);

        let settings: HashMap<u64, u64> = h3_frame::parse_settings_payload(&frames[0].1).unwrap().into_iter().collect();
        assert_eq!(settings.get(&h3_frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY), Some(&4096));
        assert_eq!(settings.get(&h3_frame::SETTINGS_QPACK_BLOCKED_STREAMS), Some(&100));
    }

    #[test]
    fn test_check_timeout_sends_probe_after_pto_expires() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;
        conn.idle_timeout = Duration::from_secs(3600);

        let keys = super::super::crypto::CryptoKeys::new(vec![0u8; 16], vec![1u8; 16], vec![2u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        conn.send_frame(PacketNumberSpace::ApplicationData, Frame::Ping).unwrap();
        conn.send().unwrap();
        assert!(conn.send_queue.is_empty());

        conn.check_timeout().unwrap();
        assert!(conn.send_queue.is_empty());

        std::thread::sleep(Duration::from_millis(110));

        conn.check_timeout().unwrap();

        let probe = conn.send_queue.pop_front().expect("a PTO probe should have been queued");
        let level = EncryptionLevel::from_packet_type(probe.header.packet_type);
        let decrypted = conn
            .crypto
            .decrypt(level, probe.header.packet_number, &probe.payload, &[])
            .unwrap();
        let (frame, _) = Frame::parse(&decrypted).unwrap();
        assert!(matches!(frame, Frame::Ping));
    }

    #[test]
    fn test_packet_number_reconstructs_correctly_with_nonzero_largest_pn() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let config = Config::default();
        let scid = ConnectionId::generate().unwrap();
        let dcid = ConnectionId::generate().unwrap();

        let mut client = Http3Connection::new_client(client_socket, server_addr, config.clone()).unwrap();
        let mut server = Http3Connection::new_server(server_socket, client_addr, scid, dcid, config).unwrap();
        client.state = ConnectionState::Active;
        server.state = ConnectionState::Active;

        let keys = super::super::crypto::CryptoKeys::new(vec![7u8; 16], vec![9u8; 16], vec![11u8; 12]);
        client.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        server.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys);

        client.next_packet_number.insert(PacketNumberSpace::ApplicationData, 300);
        client
            .recovery
            .on_ack_received(PacketNumberSpace::ApplicationData, 250, Duration::from_millis(0), vec![(250, 250)], Instant::now())
            .unwrap();
        server.largest_pn_seen.insert(PacketNumberSpace::ApplicationData, 250);

        client.send_frame(PacketNumberSpace::ApplicationData, Frame::Ping).unwrap();
        client.send().unwrap();

        server.recv().unwrap();

        assert_eq!(
            server.largest_pn_seen.get(&PacketNumberSpace::ApplicationData),
            Some(&300),
            "packet number should reconstruct to 300 using the real largest_pn, not truncate to 44"
        );
        assert!(server
            .pending_acks
            .get(&PacketNumberSpace::ApplicationData)
            .unwrap()
            .contains(&300));
    }

    #[test]
    fn test_peer_qpack_encoder_stream_updates_decoder_and_queues_ack() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;

        conn.qpack_decoder_stream_id = Some(conn.create_uni_stream().unwrap());
        let keys = super::super::crypto::CryptoKeys::new(vec![4u8; 16], vec![5u8; 16], vec![6u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        let mut peer_encoder = super::super::qpack::QpackEncoder::new(4096);
        let encoded_field_section = peer_encoder.encode(&[("x-test".to_string(), "value".to_string())]).unwrap();
        let instructions = peer_encoder.drain_instructions();
        assert!(!instructions.is_empty());

        let peer_stream_id = 7;
        conn.uni_stream_kind.insert(peer_stream_id, UniStreamKind::QpackEncoder);
        conn.peer_qpack_encoder_stream_id = Some(peer_stream_id);
        conn.uni_stream_pending.insert(peer_stream_id, instructions);

        conn.process_peer_qpack_encoder_stream(peer_stream_id).unwrap();

        let decoded = conn.qpack_decoder.decode(&encoded_field_section).unwrap();
        assert_eq!(decoded, vec![("x-test".to_string(), "value".to_string())]);

        let mut saw_ack = false;
        for packet in &conn.send_queue {
            let level = EncryptionLevel::from_packet_type(packet.header.packet_type);
            let decrypted = conn.crypto.decrypt(level, packet.header.packet_number, &packet.payload, &[]).unwrap();
            let mut offset = 0;
            while offset < decrypted.len() {
                let (frame, consumed) = Frame::parse(&decrypted[offset..]).unwrap();
                offset += consumed;
                if let Frame::Stream { stream_id, data, .. } = frame {
                    if Some(stream_id) == conn.qpack_decoder_stream_id && !data.is_empty() {
                        saw_ack = true;
                    }
                }
            }
        }
        assert!(saw_ack, "an Insert Count Increment should have been sent on our QPACK decoder stream");
    }

    #[test]
    fn test_anti_amplification_limits_server_sends_before_validation() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let scid = ConnectionId::generate().unwrap();
        let dcid = ConnectionId::generate().unwrap();
        let mut conn = Http3Connection::new_server(socket, addr, scid, dcid, config).unwrap();
        conn.state = ConnectionState::Active;
        assert!(!conn.is_address_validated());

        let keys = super::super::crypto::CryptoKeys::new(vec![1u8; 16], vec![2u8; 16], vec![3u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        conn.bytes_received_before_validation = 100;
        for _ in 0..20 {
            conn.send_frame(
                PacketNumberSpace::ApplicationData,
                Frame::Stream {
                    stream_id: 0,
                    offset: 0,
                    data: vec![0u8; 200],
                    fin: false,
                },
            )
            .unwrap();
        }

        conn.send().unwrap();

        assert!(
            conn.bytes_sent_before_validation <= 300,
            "must not send more than 3x what was received before validation, sent {}",
            conn.bytes_sent_before_validation
        );
        assert!(!conn.send_queue.is_empty(), "packets exceeding the amplification limit should remain queued, not dropped");
    }

    #[test]
    fn test_client_handles_valid_retry_and_updates_dcid() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        let original_dcid = conn.dcid.clone();
        let new_server_scid = ConnectionId::generate().unwrap();
        let token = vec![0xaa, 0xbb, 0xcc, 0xdd];

        let header = PacketHeader::new(PacketType::Retry, super::super::HTTP3_VERSION, conn.scid.clone(), new_server_scid.clone(), 0);
        let mut header_and_token = Vec::new();
        header.encode(&mut header_and_token, 0).unwrap();
        header_and_token.extend_from_slice(&token);

        let tag = super::super::crypto::compute_retry_integrity_tag(original_dcid.as_bytes(), &header_and_token).unwrap();
        let mut retry_datagram = header_and_token;
        retry_datagram.extend_from_slice(&tag);

        conn.process_datagram(&retry_datagram).unwrap();

        let (recovered_token, recovered_dcid) = conn.take_pending_retry().expect("a valid retry should be recorded");
        assert_eq!(recovered_token, token);
        assert_eq!(recovered_dcid.as_bytes(), new_server_scid.as_bytes());
        assert_eq!(conn.dcid.as_bytes(), new_server_scid.as_bytes());
    }

    #[test]
    fn test_client_rejects_retry_with_invalid_integrity_tag() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();

        let new_server_scid = ConnectionId::generate().unwrap();
        let token = vec![1, 2, 3];
        let header = PacketHeader::new(PacketType::Retry, super::super::HTTP3_VERSION, conn.scid.clone(), new_server_scid, 0);
        let mut header_and_token = Vec::new();
        header.encode(&mut header_and_token, 0).unwrap();
        header_and_token.extend_from_slice(&token);

        let bogus_odcid = ConnectionId::generate().unwrap();
        let tag = super::super::crypto::compute_retry_integrity_tag(bogus_odcid.as_bytes(), &header_and_token).unwrap();
        let mut retry_datagram = header_and_token;
        retry_datagram.extend_from_slice(&tag);

        conn.process_datagram(&retry_datagram).unwrap();
        assert!(conn.take_pending_retry().is_none(), "a retry with an invalid integrity tag must be ignored");
    }

    #[test]
    fn test_path_challenge_is_answered_with_path_response() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;

        let keys = super::super::crypto::CryptoKeys::new(vec![1u8; 16], vec![2u8; 16], vec![3u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        let challenge_data = [9u8, 8, 7, 6, 5, 4, 3, 2];
        conn.process_frame(PacketType::Short, Frame::PathChallenge { data: challenge_data }).unwrap();

        let queued = conn.send_queue.pop_front().expect("a PATH_RESPONSE should have been queued");
        let level = EncryptionLevel::from_packet_type(queued.header.packet_type);
        let decrypted = conn.crypto.decrypt(level, queued.header.packet_number, &queued.payload, &[]).unwrap();
        let (frame, _) = Frame::parse(&decrypted).unwrap();
        match frame {
            Frame::PathResponse { data } => assert_eq!(data, challenge_data),
            other => panic!("expected PathResponse, got {:?}", other),
        }
    }

    #[test]
    fn test_path_response_is_recorded() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();

        assert!(conn.last_path_response().is_none());
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        conn.process_frame(PacketType::Short, Frame::PathResponse { data }).unwrap();
        assert_eq!(conn.last_path_response(), Some(data));
    }

    #[test]
    fn test_new_connection_id_stores_and_retires_old_ones() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;

        let keys = super::super::crypto::CryptoKeys::new(vec![1u8; 16], vec![2u8; 16], vec![3u8; 12]);
        conn.crypto_mut().client_keys.insert(EncryptionLevel::Application, keys.clone());
        conn.crypto_mut().server_keys.insert(EncryptionLevel::Application, keys);

        conn.process_frame(
            PacketType::Short,
            Frame::NewConnectionId {
                sequence: 0,
                retire_prior_to: 0,
                connection_id: ConnectionId::generate().unwrap(),
                stateless_reset_token: [0u8; 16],
            },
        )
        .unwrap();
        assert_eq!(conn.peer_connection_ids().len(), 1);
        assert!(conn.peer_connection_ids().contains_key(&0));

        let new_cid = ConnectionId::generate().unwrap();
        conn.process_frame(
            PacketType::Short,
            Frame::NewConnectionId {
                sequence: 1,
                retire_prior_to: 1,
                connection_id: new_cid,
                stateless_reset_token: [1u8; 16],
            },
        )
        .unwrap();

        assert!(!conn.peer_connection_ids().contains_key(&0));
        assert!(conn.peer_connection_ids().contains_key(&1));

        let mut saw_retire = false;
        for packet in &conn.send_queue {
            let level = EncryptionLevel::from_packet_type(packet.header.packet_type);
            let decrypted = conn.crypto.decrypt(level, packet.header.packet_number, &packet.payload, &[]).unwrap();
            let (frame, _) = Frame::parse(&decrypted).unwrap();
            if let Frame::RetireConnectionId { sequence } = frame {
                assert_eq!(sequence, 0);
                saw_retire = true;
            }
        }
        assert!(saw_retire, "a RETIRE_CONNECTION_ID should have been sent for the superseded sequence 0");
    }

    #[test]
    fn test_retire_connection_id_removes_entry() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();
        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();

        conn.process_frame(
            PacketType::Short,
            Frame::NewConnectionId {
                sequence: 5,
                retire_prior_to: 0,
                connection_id: ConnectionId::generate().unwrap(),
                stateless_reset_token: [0u8; 16],
            },
        )
        .unwrap();
        assert!(conn.peer_connection_ids().contains_key(&5));

        conn.process_frame(PacketType::Short, Frame::RetireConnectionId { sequence: 5 }).unwrap();
        assert!(!conn.peer_connection_ids().contains_key(&5));
    }

    #[test]
    fn test_process_peer_control_stream_populates_peer_settings() {
        let socket = create_test_socket();
        let addr = create_test_addr();
        let config = Config::default();

        let mut conn = Http3Connection::new_client(socket, addr, config).unwrap();
        conn.state = ConnectionState::Active;

        let mut bytes = h3_frame::encode_stream_type(h3_frame::H3_STREAM_TYPE_CONTROL);
        bytes.extend_from_slice(&h3_frame::encode_settings_frame(&[(
            h3_frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            8192,
        )]));

        conn.handle_stream_frame(3, 0, bytes, false).unwrap();
        conn.poll_peer_uni_streams().unwrap();

        assert_eq!(conn.peer_control_stream_id, Some(3));
        assert_eq!(
            conn.peer_settings.get(&h3_frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY),
            Some(&8192)
        );
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