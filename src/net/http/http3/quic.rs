use super::connection::Http3Connection;
use super::error::{Error, ErrorCode, Result};
use super::packet::{Packet, PacketType};
use super::quic_tls::{CryptoAction, QuicTlsState};
use super::stream::StreamId;
use super::{Config, ConnectionId, Role};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::udp::UdpSocket;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const QUIC_STATS_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_QUIC_STATS_BLOB_V1";
const QUIC_STATS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_QUIC_STATS_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureQuicStatsBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum StreamEvent {
    DataReady(StreamId),
    Finished(StreamId),
    Reset(StreamId, u64),
}

pub struct QuicClient {
    config: Config,
    connections: HashMap<SocketAddr, Http3Connection>,
    default_timeout: Duration,
    tls_states: HashMap<SocketAddr, QuicTlsState>,
}

impl QuicClient {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            tls_states: HashMap::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn connect(&mut self, server_addr: SocketAddr) -> Result<&mut Http3Connection> {
        self.connect_with_sni(server_addr, server_addr.ip().to_string())
    }

    pub fn connect_with_sni(&mut self, server_addr: SocketAddr, server_name: String) -> Result<&mut Http3Connection> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(server_addr)?;
        socket.set_read_timeout(Some(self.default_timeout))?;
        socket.set_write_timeout(Some(self.default_timeout))?;

        let mut connection = Http3Connection::new_client(socket, server_addr, self.config.clone())?;
        let mut tls_state = QuicTlsState::new_client(Some(server_name));
        tls_state.set_alpn_protocols(vec!["h3".to_string()]);
        tls_state.set_transport_params(self.build_transport_params());
        tls_state.start_handshake(connection.crypto_mut())?;
        while let Some((pn_space, crypto_data)) = tls_state.next_crypto_data() {
            connection.send_crypto(pn_space, crypto_data)?;
        }

        connection.send()?;
        let deadline = Instant::now() + self.default_timeout;
        loop {
            if Instant::now() > deadline {
                return Err(Error::Tls("Handshake timed out".to_string()));
            }

            connection.recv()?;
            let pending = connection.get_pending_crypto();
            for (offset, data) in pending {
                let actions = tls_state.process_crypto_data(offset, data, connection.crypto_mut())?;
                for action in actions {
                    match action {
                        CryptoAction::InstallHandshakeKeys => {
                            connection.on_handshake_keys_ready()?;
                        }
                        CryptoAction::InstallApplicationKeys => {
                            connection.on_application_keys_ready()?;
                        }
                        CryptoAction::HandshakeComplete => {
                            while let Some((pn_space, crypto_data)) = tls_state.next_crypto_data() {
                                connection.send_crypto(pn_space, crypto_data)?;
                            }

                            connection.send()?;
                            self.tls_states.insert(server_addr, tls_state);
                            self.connections.insert(server_addr, connection);
                            
                            return Ok(self.connections.get_mut(&server_addr).unwrap());
                        }
                        CryptoAction::SendCryptoData => {
                            while let Some((pn_space, crypto_data)) = tls_state.next_crypto_data() {
                                connection.send_crypto(pn_space, crypto_data)?;
                            }

                            connection.send()?;
                        }
                        CryptoAction::UpdateKeys => {
                            connection.update_keys()?;
                        }
                    }
                }
            }

            if tls_state.is_complete() {
                break;
            }

            if tls_state.has_timed_out() {
                return Err(Error::Tls("TLS handshake timed out".to_string()));
            }
        }

        self.tls_states.insert(server_addr, tls_state);
        self.connections.insert(server_addr, connection);
        Ok(self.connections.get_mut(&server_addr).unwrap())
    }

    fn build_transport_params(&self) -> Vec<u8> {
        let mut params = Vec::new();
        Self::encode_transport_param(
            &mut params,
            0x01,
            &(self.config.max_idle_timeout.as_millis() as u64).to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x03,
            &(self.config.max_udp_payload_size as u64).to_be_bytes(),
        );
        Self::encode_transport_param(&mut params, 0x04, &self.config.initial_max_data.to_be_bytes());
        Self::encode_transport_param(
            &mut params,
            0x05,
            &self.config.initial_max_stream_data_bidi_local.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x06,
            &self.config.initial_max_stream_data_bidi_remote.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x07,
            &self.config.initial_max_stream_data_uni.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x08,
            &self.config.initial_max_streams_bidi.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x09,
            &self.config.initial_max_streams_uni.to_be_bytes(),
        );
        params
    }

    fn encode_transport_param(buffer: &mut Vec<u8>, param_id: u64, value: &[u8]) {
        Self::encode_varint(buffer, param_id);
        Self::encode_varint(buffer, value.len() as u64);
        buffer.extend_from_slice(value);
    }

    fn encode_varint(buffer: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buffer.push(value as u8);
        } else if value < 16384 {
            buffer.extend_from_slice(&((value | 0x4000) as u16).to_be_bytes());
        } else if value < 1073741824 {
            buffer.extend_from_slice(&((value | 0x80000000) as u32).to_be_bytes());
        } else {
            buffer.extend_from_slice(&((value | 0xC000000000000000) as u64).to_be_bytes());
        }
    }

    pub fn get_connection(&mut self, server_addr: SocketAddr) -> Option<&mut Http3Connection> {
        self.connections.get_mut(&server_addr)
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn cleanup_closed(&mut self) {
        self.connections.retain(|_, conn| !conn.is_closed());
        let active: Vec<SocketAddr> = self.connections.keys().cloned().collect();
        self.tls_states.retain(|addr, _| active.contains(addr));
    }

    pub fn close_connection(&mut self, server_addr: SocketAddr) -> Result<()> {
        if let Some(mut conn) = self.connections.remove(&server_addr) {
            conn.close(ErrorCode::NoError, b"Client closing")?;
        }

        self.tls_states.remove(&server_addr);
        Ok(())
    }

    pub fn send_request(&mut self, server_addr: SocketAddr, headers: Vec<(String, String)>, body: Option<Vec<u8>>,) -> Result<StreamId> {
        let is_established = self.connections.get(&server_addr).ok_or_else(|| {
            Error::InvalidOperation("Connection not found".to_string())
        })?.is_established();

        if !is_established {
            return Err(Error::InvalidOperation(
                "Connection not established".to_string(),
            ));
        }

        let conn = self.connections.get_mut(&server_addr).unwrap();
        let stream_id = conn.create_stream()?;
        let mut header_block = Vec::new();
        for (name, value) in headers {
            header_block.extend_from_slice(name.as_bytes());
            header_block.push(b':');
            header_block.push(b' ');
            header_block.extend_from_slice(value.as_bytes());
            header_block.extend_from_slice(b"\r\n");
        }

        conn.stream_send(stream_id, &header_block, false)?;
        conn.stream_send(stream_id, b"\r\n", body.is_none())?;
        if let Some(data) = body {
            conn.stream_send(stream_id, &data, true)?;
        }

        conn.send()?;
        Ok(stream_id)
    }

    pub fn receive_response(&mut self, server_addr: SocketAddr, stream_id: StreamId) -> Result<Vec<u8>> {
        let conn = self.connections.get_mut(&server_addr).ok_or_else(|| {
            Error::InvalidOperation("Connection not found".to_string())
        })?;

        let mut response = Vec::new();
        let mut buffer = vec![0u8; 8192];
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() > deadline {
                return Err(Error::Timeout);
            }

            conn.recv()?;
            match conn.stream_recv(stream_id, &mut buffer) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(Error::Done) => break,
                Err(Error::WouldBlock) => continue,
                Err(e) => return Err(e),
            }

            if let Some(stream) = conn.stream(stream_id) {
                if stream.fin_received() {
                    break;
                }
            }
        }

        Ok(response)
    }
}

pub struct QuicServer {
    config: Config,
    socket: UdpSocket,
    connections: HashMap<ConnectionId, Http3Connection>,
    tls_states: HashMap<ConnectionId, QuicTlsState>,
    pending_connections: HashMap<SocketAddr, PendingConnection>,
    bind_addr: SocketAddr,
}

struct PendingConnection {
    scid: ConnectionId,
    dcid: ConnectionId,
    created_at: Instant,
}

impl PendingConnection {
    fn new(scid: ConnectionId, dcid: ConnectionId) -> Self {
        Self {
            scid,
            dcid,
            created_at: Instant::now(),
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.created_at.elapsed() > timeout
    }
}

impl QuicServer {
    pub fn bind(addr: SocketAddr, config: Config) -> Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        Ok(Self {
            config,
            socket,
            connections: HashMap::new(),
            tls_states: HashMap::new(),
            pending_connections: HashMap::new(),
            bind_addr: addr,
        })
    }

    pub fn accept(&mut self) -> Result<Option<(ConnectionId, SocketAddr)>> {
        let mut buffer = vec![0u8; 65535];
        let (size, peer_addr) = match self.socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                return Ok(None)
            }
            Err(e) => return Err(Error::Io(e)),
        };

        buffer.truncate(size);
        let packet = Packet::parse(&buffer)?;
        if packet.header.packet_type == PacketType::Initial {
            return self.handle_initial_packet(packet, peer_addr);
        }

        let conn_id = packet.header.dcid.clone();
        if self.connections.contains_key(&conn_id) {
            self.handle_packet_for_connection(&conn_id, &buffer)?;
        }

        Ok(None)
    }

    fn handle_initial_packet(&mut self, packet: Packet, peer_addr: SocketAddr) -> Result<Option<(ConnectionId, SocketAddr)>> {
        let scid = ConnectionId::generate()?;
        let dcid = packet.header.scid.clone();

        let client_socket = UdpSocket::bind("0.0.0.0:0")?;
        client_socket.connect(peer_addr)?;
        client_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        client_socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        let connection = Http3Connection::new_server(
            client_socket,
            peer_addr,
            scid.clone(),
            dcid.clone(),
            self.config.clone(),
        )?;

        let mut tls_state = QuicTlsState::new_server();
        tls_state.set_alpn_protocols(vec!["h3".to_string()]);
        tls_state.set_transport_params(self.build_transport_params());

        self.pending_connections.insert(peer_addr, PendingConnection::new(scid.clone(), dcid));
        self.connections.insert(scid.clone(), connection);
        self.tls_states.insert(scid.clone(), tls_state);

        Ok(Some((scid, peer_addr)))
    }

    fn handle_packet_for_connection(&mut self, conn_id: &ConnectionId, _data: &[u8]) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(conn_id) {
            conn.recv()?;
        }

        Ok(())
    }

    fn build_transport_params(&self) -> Vec<u8> {
        let mut params = Vec::new();
        Self::encode_transport_param(
            &mut params,
            0x01,
            &(self.config.max_idle_timeout.as_millis() as u64).to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x03,
            &(self.config.max_udp_payload_size as u64).to_be_bytes(),
        );
        Self::encode_transport_param(&mut params, 0x04, &self.config.initial_max_data.to_be_bytes());
        Self::encode_transport_param(
            &mut params,
            0x05,
            &self.config.initial_max_stream_data_bidi_local.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x06,
            &self.config.initial_max_stream_data_bidi_remote.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x07,
            &self.config.initial_max_stream_data_uni.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x08,
            &self.config.initial_max_streams_bidi.to_be_bytes(),
        );
        Self::encode_transport_param(
            &mut params,
            0x09,
            &self.config.initial_max_streams_uni.to_be_bytes(),
        );
        params
    }

    fn encode_transport_param(buffer: &mut Vec<u8>, param_id: u64, value: &[u8]) {
        Self::encode_varint(buffer, param_id);
        Self::encode_varint(buffer, value.len() as u64);
        buffer.extend_from_slice(value);
    }

    fn encode_varint(buffer: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buffer.push(value as u8);
        } else if value < 16384 {
            buffer.extend_from_slice(&((value | 0x4000) as u16).to_be_bytes());
        } else if value < 1073741824 {
            buffer.extend_from_slice(&((value | 0x80000000) as u32).to_be_bytes());
        } else {
            buffer.extend_from_slice(&((value | 0xC000000000000000) as u64).to_be_bytes());
        }
    }

    pub fn get_connection(&mut self, connection_id: &ConnectionId) -> Option<&mut Http3Connection> {
        self.connections.get_mut(connection_id)
    }

    pub fn cleanup_expired(&mut self) {
        let timeout = Duration::from_secs(10);
        self.pending_connections.retain(|_, p| !p.is_expired(timeout));

        let closed: Vec<ConnectionId> = self.connections.iter().filter(|(_, c)| c.is_closed()).map(|(id, _)| id.clone()).collect();
        for id in closed {
            self.connections.remove(&id);
            self.tls_states.remove(&id);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_connections.len()
    }

    pub fn close_connection(&mut self, connection_id: &ConnectionId) -> Result<()> {
        if let Some(mut conn) = self.connections.remove(connection_id) {
            conn.close(ErrorCode::NoError, b"Server closing")?;
        }

        self.tls_states.remove(connection_id);
        Ok(())
    }

    pub fn process_connections(&mut self) -> Result<Vec<(ConnectionId, Vec<StreamEvent>)>> {
        let mut events = Vec::new();
        let ids: Vec<ConnectionId> = self.connections.keys().cloned().collect();
        for id in ids {
            if let Some(conn) = self.connections.get_mut(&id) {
                conn.recv().ok();
            }

            let stream_events = self.collect_stream_events_for(&id)?;
            if !stream_events.is_empty() {
                events.push((id, stream_events));
            }
        }

        Ok(events)
    }

    fn collect_stream_events_for(&self, conn_id: &ConnectionId) -> Result<Vec<StreamEvent>> {
        match self.connections.get(conn_id) {
            Some(conn) => self.collect_stream_events(conn),
            None => Ok(Vec::new()),
        }
    }

    fn collect_stream_events(&self, conn: &Http3Connection) -> Result<Vec<StreamEvent>> {
        let mut events = Vec::new();
        for (stream_id, stream) in &conn.streams {
            if stream.readable() > 0 {
                events.push(StreamEvent::DataReady(*stream_id));
            }

            if stream.is_finished() {
                events.push(StreamEvent::Finished(*stream_id));
            }

            if let Some(error_code) = stream.error_code() {
                events.push(StreamEvent::Reset(*stream_id, error_code));
            }
        }

        Ok(events)
    }
}

pub struct QuicEndpoint {
    role: Role,
    config: Config,
    socket: UdpSocket,
    connections: HashMap<ConnectionId, Http3Connection>,
    tls_states: HashMap<ConnectionId, QuicTlsState>,
}

impl QuicEndpoint {
    pub fn new(role: Role, bind_addr: SocketAddr, config: Config) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        Ok(Self {
            role,
            config,
            socket,
            connections: HashMap::new(),
            tls_states: HashMap::new(),
        })
    }

    pub fn connect(&mut self, server_addr: SocketAddr) -> Result<ConnectionId> {
        if self.role != Role::Client {
            return Err(Error::InvalidOperation(
                "Only clients can connect".to_string(),
            ));
        }

        let scid = ConnectionId::generate()?;

        let client_socket = UdpSocket::bind("0.0.0.0:0")?;
        client_socket.connect(server_addr)?;
        client_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        client_socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut connection = Http3Connection::new_client(client_socket, server_addr, self.config.clone())?;
        let mut tls_state = QuicTlsState::new_client(Some(server_addr.ip().to_string()));
        tls_state.set_alpn_protocols(vec!["h3".to_string()]);
        tls_state.start_handshake(connection.crypto_mut())?;

        connection.connect()?;

        self.connections.insert(scid.clone(), connection);
        self.tls_states.insert(scid.clone(), tls_state);

        Ok(scid)
    }

    pub fn accept(&mut self) -> Result<Option<ConnectionId>> {
        if self.role != Role::Server {
            return Err(Error::InvalidOperation(
                "Only servers can accept".to_string(),
            ));
        }

        let mut buffer = vec![0u8; 65535];
        let (size, peer_addr) = match self.socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                return Ok(None)
            }
            Err(e) => return Err(Error::Io(e)),
        };

        buffer.truncate(size);
        let packet = Packet::parse(&buffer)?;
        if packet.header.packet_type == PacketType::Initial {
            let scid = ConnectionId::generate()?;
            let dcid = packet.header.scid.clone();

            let client_socket = UdpSocket::bind("0.0.0.0:0")?;
            client_socket.connect(peer_addr)?;
            client_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            client_socket.set_write_timeout(Some(Duration::from_secs(5)))?;

            let connection = Http3Connection::new_server(
                client_socket,
                peer_addr,
                scid.clone(),
                dcid,
                self.config.clone(),
            )?;

            let mut tls_state = QuicTlsState::new_server();
            tls_state.set_alpn_protocols(vec!["h3".to_string()]);

            self.connections.insert(scid.clone(), connection);
            self.tls_states.insert(scid.clone(), tls_state);

            return Ok(Some(scid));
        }

        Ok(None)
    }

    pub fn get_connection(&mut self, conn_id: &ConnectionId) -> Option<&mut Http3Connection> {
        self.connections.get_mut(conn_id)
    }

    pub fn remove_connection(&mut self, conn_id: &ConnectionId) {
        self.connections.remove(conn_id);
        self.tls_states.remove(conn_id);
    }

    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().cloned().collect()
    }

    pub fn is_client(&self) -> bool {
        self.role == Role::Client
    }

    pub fn is_server(&self) -> bool {
        self.role == Role::Server
    }
}

pub struct QuicConnectionManager {
    client_connections: HashMap<SocketAddr, Http3Connection>,
    server_connections: HashMap<ConnectionId, Http3Connection>,
    tls_states: HashMap<String, QuicTlsState>,
    config: Config,
}

impl QuicConnectionManager {
    pub fn new(config: Config) -> Self {
        Self {
            client_connections: HashMap::new(),
            server_connections: HashMap::new(),
            tls_states: HashMap::new(),
            config,
        }
    }

    pub fn create_client_connection(&mut self, server_addr: SocketAddr) -> Result<&mut Http3Connection> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(server_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut connection = Http3Connection::new_client(socket, server_addr, self.config.clone())?;
        let mut tls_state = QuicTlsState::new_client(Some(server_addr.ip().to_string()));
        tls_state.set_alpn_protocols(vec!["h3".to_string()]);
        tls_state.start_handshake(connection.crypto_mut())?;

        connection.connect()?;

        let key = format!("client_{}", server_addr);
        self.tls_states.insert(key, tls_state);
        self.client_connections.insert(server_addr, connection);

        Ok(self.client_connections.get_mut(&server_addr).unwrap())
    }

    pub fn add_server_connection(&mut self, conn_id: ConnectionId, connection: Http3Connection) {
        self.server_connections.insert(conn_id, connection);
    }

    pub fn get_client_connection(&mut self, server_addr: &SocketAddr) -> Option<&mut Http3Connection> {
        self.client_connections.get_mut(server_addr)
    }

    pub fn get_server_connection(&mut self, conn_id: &ConnectionId) -> Option<&mut Http3Connection> {
        self.server_connections.get_mut(conn_id)
    }

    pub fn remove_client_connection(&mut self, server_addr: &SocketAddr) {
        self.client_connections.remove(server_addr);
        self.tls_states.remove(&format!("client_{}", server_addr));
    }

    pub fn remove_server_connection(&mut self, conn_id: &ConnectionId) {
        self.server_connections.remove(conn_id);
        self.tls_states.remove(&format!("server_{}", conn_id));
    }

    pub fn client_count(&self) -> usize {
        self.client_connections.len()
    }

    pub fn server_count(&self) -> usize {
        self.server_connections.len()
    }

    pub fn total_count(&self) -> usize {
        self.client_count() + self.server_count()
    }

    pub fn cleanup_closed(&mut self) {
        let closed_clients: Vec<SocketAddr> = self.client_connections.iter().filter(|(_, c)| c.is_closed()).map(|(addr, _)| *addr).collect();
        for addr in closed_clients {
            self.client_connections.remove(&addr);
            self.tls_states.remove(&format!("client_{}", addr));
        }

        let closed_servers: Vec<ConnectionId> = self.server_connections.iter().filter(|(_, c)| c.is_closed()).map(|(id, _)| id.clone()).collect();
        for id in closed_servers {
            self.server_connections.remove(&id);
            self.tls_states.remove(&format!("server_{}", id));
        }
    }

    pub fn process_all(&mut self) -> Result<()> {
        for conn in self.client_connections.values_mut() {
            conn.recv().ok();
        }

        for conn in self.server_connections.values_mut() {
            conn.recv().ok();
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct QuicStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub closed_connections: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
}

impl QuicStats {
    pub fn new() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            closed_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
        }
    }

    pub fn from_connections(connections: &HashMap<ConnectionId, Http3Connection>) -> Self {
        let total = connections.len();
        let active = connections.values().filter(|c| c.is_established()).count();
        let closed = connections.values().filter(|c| c.is_closed()).count();

        let mut stats = Self::new();
        stats.total_connections = total;
        stats.active_connections = active;
        stats.closed_connections = closed;
        for conn in connections.values() {
            let s = conn.stats();
            stats.bytes_sent += s.bytes_sent;
            stats.bytes_received += s.bytes_received;
            stats.packets_sent += s.packets_sent;
            stats.packets_received += s.packets_received;
            stats.packets_lost += s.packets_lost;
        }

        stats
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureQuicStatsBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_quic_stats(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure quic-stats nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_quic_stats_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureQuicStatsBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = QUIC_STATS_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix,
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&encoded_payload);

        Ok((meta, blob))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureQuicStatsBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_quic_stats_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureQuicStatsBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_quic_stats_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-stats nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-stats digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-stats tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-stats digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_quic_stats_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure quic-stats blob tag verification failed",
            ));
        }

        let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if raw_payload.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "secure quic-stats raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure quic-stats blob digest verification failed",
            ));
        }

        let stats = deserialize_quic_stats(&raw_payload)?;
        Ok((meta, stats))
    }
}

impl Default for QuicStats {
    fn default() -> Self {
        Self::new()
    }
}

pub fn select_secure_quic_stats_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_quic_stats(stats: &QuicStats, algorithm: CompressionAlgorithm) -> io::Result<(SecureQuicStatsBlobMeta, Vec<u8>)> {
    stats.to_secure_blob(algorithm)
}

pub fn encode_secure_quic_stats_auto(stats: &QuicStats, accept_encoding: &str) -> io::Result<(SecureQuicStatsBlobMeta, Vec<u8>)> {
    stats.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_quic_stats(data: &[u8]) -> io::Result<(SecureQuicStatsBlobMeta, QuicStats)> {
    QuicStats::from_secure_blob(data)
}

fn serialize_quic_stats(stats: &QuicStats) -> Vec<u8> {
    format!(
        "total-connections={}\nactive-connections={}\nclosed-connections={}\nbytes-sent={}\nbytes-received={}\npackets-sent={}\npackets-received={}\npackets-lost={}\n",
        stats.total_connections,
        stats.active_connections,
        stats.closed_connections,
        stats.bytes_sent,
        stats.bytes_received,
        stats.packets_sent,
        stats.packets_received,
        stats.packets_lost
    )
    .into_bytes()
}

fn deserialize_quic_stats(raw_payload: &[u8]) -> io::Result<QuicStats> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure quic-stats payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-stats payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let parse_usize = |key: &str| -> io::Result<usize> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-stats payload", key),
            )
        })?.parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in quic-stats payload", key),
            )
        })
    };

    let parse_u64 = |key: &str| -> io::Result<u64> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-stats payload", key),
            )
        })?.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in quic-stats payload", key),
            )
        })
    };

    Ok(QuicStats {
        total_connections: parse_usize("total-connections")?,
        active_connections: parse_usize("active-connections")?,
        closed_connections: parse_usize("closed-connections")?,
        bytes_sent: parse_u64("bytes-sent")?,
        bytes_received: parse_u64("bytes-received")?,
        packets_sent: parse_u64("packets-sent")?,
        packets_received: parse_u64("packets-received")?,
        packets_lost: parse_u64("packets-lost")?,
    })
}

fn compute_quic_stats_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(QUIC_STATS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(QUIC_STATS_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-stats header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-stats header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "quic-stats blob missing header/body separator",
    ))
}

fn parse_secure_quic_stats_meta(header: &str, body_len: usize) -> io::Result<SecureQuicStatsBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != QUIC_STATS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure quic-stats blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure quic-stats header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", v.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();
                
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in quic-stats blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in quic-stats blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in quic-stats blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureQuicStatsBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in secure quic-stats blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in secure quic-stats blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in secure quic-stats blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in secure quic-stats blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure quic-stats blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in secure quic-stats blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure quic-stats encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_quic_stats_roundtrip_identity() {
        let stats = QuicStats {
            total_connections: 10,
            active_connections: 7,
            closed_connections: 3,
            bytes_sent: 12_345,
            bytes_received: 67_890,
            packets_sent: 111,
            packets_received: 222,
            packets_lost: 5,
        };

        let (meta, blob) = stats
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure quic-stats blob");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_stats) =
            QuicStats::from_secure_blob(&blob).expect("failed to decode secure quic-stats blob");

        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(decoded_stats.total_connections, stats.total_connections);
        assert_eq!(decoded_stats.active_connections, stats.active_connections);
        assert_eq!(decoded_stats.closed_connections, stats.closed_connections);
        assert_eq!(decoded_stats.bytes_sent, stats.bytes_sent);
        assert_eq!(decoded_stats.bytes_received, stats.bytes_received);
        assert_eq!(decoded_stats.packets_sent, stats.packets_sent);
        assert_eq!(decoded_stats.packets_received, stats.packets_received);
        assert_eq!(decoded_stats.packets_lost, stats.packets_lost);
    }

    #[test]
    fn test_secure_quic_stats_roundtrip_compressed() {
        let stats = QuicStats {
            total_connections: 200,
            active_connections: 150,
            closed_connections: 50,
            bytes_sent: 9_999_999,
            bytes_received: 8_888_888,
            packets_sent: 3333,
            packets_received: 4444,
            packets_lost: 77,
        };

        let (_meta, blob) = stats
            .to_secure_blob(CompressionAlgorithm::Gzip)
            .expect("failed to encode compressed secure quic-stats blob");

        let (_decoded_meta, decoded_stats) = QuicStats::from_secure_blob(&blob)
            .expect("failed to decode compressed secure quic-stats blob");

        assert_eq!(decoded_stats.total_connections, stats.total_connections);
        assert_eq!(decoded_stats.active_connections, stats.active_connections);
        assert_eq!(decoded_stats.closed_connections, stats.closed_connections);
        assert_eq!(decoded_stats.bytes_sent, stats.bytes_sent);
        assert_eq!(decoded_stats.bytes_received, stats.bytes_received);
        assert_eq!(decoded_stats.packets_sent, stats.packets_sent);
        assert_eq!(decoded_stats.packets_received, stats.packets_received);
        assert_eq!(decoded_stats.packets_lost, stats.packets_lost);
    }

    #[test]
    fn test_secure_quic_stats_tamper_detected() {
        let stats = QuicStats {
            total_connections: 1,
            active_connections: 1,
            closed_connections: 0,
            bytes_sent: 100,
            bytes_received: 200,
            packets_sent: 10,
            packets_received: 20,
            packets_lost: 0,
        };

        let (_meta, mut blob) = stats
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure quic-stats blob");

        let last = blob.len().checked_sub(1).expect("blob should not be empty");
        blob[last] ^= 0x01;

        let result = QuicStats::from_secure_blob(&blob);
        assert!(result.is_err());
    }
}