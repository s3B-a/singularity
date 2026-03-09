use super::crypto::{CryptoState, EncryptionLevel};
use super::error::{Error, ErrorCode, Result};
use super::frame::Frame;
use super::packet::{Packet, PacketHeader, PacketType, PacketNumberSpace};
use super::stream::{Stream, StreamId};
use super::recovery::RecoveryManager;
use super::{Config, ConnectionId, ConnectionState, Role, TransportParams};
use crate::net::udp::UdpSocket;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const MAX_DATAGRAM_SIZE: usize = 1350;

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
            max_data: 0,
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
            return Err(Error::InvalidOperation("Only client can initiate connection".to_string()));
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
                    return Err(Error::InvalidOperation("Packet from unexpected peer".to_string()));
                }

                buffer.truncate(size);
                self.process_datagram(&buffer)?;
                self.last_activity = Instant::now();
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(Error::WouldBlock);
            },
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
                self.handle_crypto_frame(offset, data)?;
            },
            Frame::Stream { stream_id, offset, data, fin } => {
                self.handle_stream_frame(stream_id, offset, data, fin)?;
            },
            Frame::Ack { largest_ack, ack_delay, ranges, .. } => {
                self.handle_ack_frame(header, largest_ack, ack_delay, ranges)?;
            },
            Frame::ConnectionClose { error_code, reason, .. } => {
                self.handle_connection_close(error_code, reason)?;
            },
            Frame::MaxData { max } => {
                self.max_data = max;
            },
            Frame::MaxStreamData { stream_id, max } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.update_send_max_offset(max)?;
                }
            },
            Frame::ResetStream { stream_id, error_code, .. } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.handle_reset(error_code)?;
                }
            },
            Frame::StopSending { stream_id, error_code } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.handle_stop_sending(error_code)?;
                }
            },
            Frame::HandshakeDone => {
                if self.role == Role::Client {
                    self.on_handshake_complete()?;
                }
            },
            _ => {},
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
        let frame = Frame::Crypto {
            offset: 0,
            data,
        };

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

    fn handle_crypto_frame(&mut self, offset: u64, data: Vec<u8>) -> Result<()> {
        self.crypto.handle_frame(offset, data)?;
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
        self.recovery.on_ack_received(pn_space, largest_ack, delay, acked_ranges, Instant::now())?;
        
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
        let mut payload = Vec::new();
        for (id, value) in &self.local_settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }

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
            return Err(Error::InvalidOperation("Connection is not active".to_string()));
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

        self.send_frame(PacketNumberSpace::ApplicationData, frame)?;

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
        assert_eq!(conn.state, ConnectionState::Closing);
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
}