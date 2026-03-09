use super::connection::Http3Connection;
use super::error::{Error, ErrorCode, Result};
use super::packet::{Packet, PacketType};
use super::stream::StreamId;
use super::quic_tls::{QuicTlsState, CryptoAction};
use super::{Config, ConnectionId, Role};
use crate::net::udp::UdpSocket;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

    pub fn connect_with_sni(
        &mut self,
        server_addr: SocketAddr,
        server_name: String,
    ) -> Result<&mut Http3Connection> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(server_addr)?;
        socket.set_read_timeout(Some(self.default_timeout))?;
        socket.set_write_timeout(Some(self.default_timeout))?;

        // Http3Connection::new_client takes (socket, peer_addr, config)
        let mut connection = Http3Connection::new_client(
            socket,
            server_addr,
            self.config.clone(),
        )?;

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
                let actions =
                    tls_state.process_crypto_data(offset, data, connection.crypto_mut())?;

                for action in actions {
                    match action {
                        CryptoAction::InstallHandshakeKeys => {
                            connection.on_handshake_keys_ready()?;
                        }
                        CryptoAction::InstallApplicationKeys => {
                            connection.on_application_keys_ready()?;
                        }
                        CryptoAction::HandshakeComplete => {
                            while let Some((pn_space, crypto_data)) =
                                tls_state.next_crypto_data()
                            {
                                connection.send_crypto(pn_space, crypto_data)?;
                            }
                            connection.send()?;

                            self.tls_states.insert(server_addr, tls_state);
                            self.connections.insert(server_addr, connection);
                            return Ok(self.connections.get_mut(&server_addr).unwrap());
                        }
                        CryptoAction::SendCryptoData => {
                            while let Some((pn_space, crypto_data)) =
                                tls_state.next_crypto_data()
                            {
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

    pub fn send_request(
        &mut self,
        server_addr: SocketAddr,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<StreamId> {
        // Split immutable check from mutable borrow to avoid double-borrow
        let is_established = self
            .connections
            .get(&server_addr)
            .ok_or_else(|| Error::InvalidOperation("Connection not found".to_string()))?
            .is_established();

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

    pub fn receive_response(
        &mut self,
        server_addr: SocketAddr,
        stream_id: StreamId,
    ) -> Result<Vec<u8>> {
        let conn = self
            .connections
            .get_mut(&server_addr)
            .ok_or_else(|| Error::InvalidOperation("Connection not found".to_string()))?;

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
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(None)
            }
            Err(e) => return Err(Error::Io(e)),
        };

        buffer.truncate(size);
        let packet = Packet::parse(&buffer)?;

        if packet.header.packet_type == PacketType::Initial {
            return self.handle_initial_packet(packet, peer_addr);
        }

        // Route to existing connection — take the conn_id by value to avoid borrow conflict
        let conn_id = packet.header.dcid.clone();
        if self.connections.contains_key(&conn_id) {
            self.handle_packet_for_connection(&conn_id, &buffer)?;
        }

        Ok(None)
    }

    fn handle_initial_packet(
        &mut self,
        packet: Packet,
        peer_addr: SocketAddr,
    ) -> Result<Option<(ConnectionId, SocketAddr)>> {
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

        self.pending_connections.insert(
            peer_addr,
            PendingConnection::new(scid.clone(), dcid),
        );
        self.connections.insert(scid.clone(), connection);
        self.tls_states.insert(scid.clone(), tls_state);

        Ok(Some((scid, peer_addr)))
    }

    fn handle_packet_for_connection(
        &mut self,
        conn_id: &ConnectionId,
        _data: &[u8],
    ) -> Result<()> {
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
        self.pending_connections
            .retain(|_, p| !p.is_expired(timeout));

        let closed: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|(_, c)| c.is_closed())
            .map(|(id, _)| id.clone())
            .collect();

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

        // Collect IDs first to avoid simultaneous mutable + immutable borrow
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

        let mut connection = Http3Connection::new_client(
            client_socket,
            server_addr,
            self.config.clone(),
        )?;

        let mut tls_state =
            QuicTlsState::new_client(Some(server_addr.ip().to_string()));
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
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
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

    pub fn create_client_connection(
        &mut self,
        server_addr: SocketAddr,
    ) -> Result<&mut Http3Connection> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(server_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut connection = Http3Connection::new_client(
            socket,
            server_addr,
            self.config.clone(),
        )?;

        let mut tls_state =
            QuicTlsState::new_client(Some(server_addr.ip().to_string()));
        tls_state.set_alpn_protocols(vec!["h3".to_string()]);
        tls_state.start_handshake(connection.crypto_mut())?;

        connection.connect()?;

        let key = format!("client_{}", server_addr);
        self.tls_states.insert(key, tls_state);
        self.client_connections.insert(server_addr, connection);

        Ok(self.client_connections.get_mut(&server_addr).unwrap())
    }

    pub fn add_server_connection(
        &mut self,
        conn_id: ConnectionId,
        connection: Http3Connection,
    ) {
        self.server_connections.insert(conn_id, connection);
    }

    pub fn get_client_connection(
        &mut self,
        server_addr: &SocketAddr,
    ) -> Option<&mut Http3Connection> {
        self.client_connections.get_mut(server_addr)
    }

    pub fn get_server_connection(
        &mut self,
        conn_id: &ConnectionId,
    ) -> Option<&mut Http3Connection> {
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
        // Collect closed client addrs first to remove tls_states without borrow conflict
        let closed_clients: Vec<SocketAddr> = self
            .client_connections
            .iter()
            .filter(|(_, c)| c.is_closed())
            .map(|(addr, _)| *addr)
            .collect();

        for addr in closed_clients {
            self.client_connections.remove(&addr);
            self.tls_states.remove(&format!("client_{}", addr));
        }

        let closed_servers: Vec<ConnectionId> = self
            .server_connections
            .iter()
            .filter(|(_, c)| c.is_closed())
            .map(|(id, _)| id.clone())
            .collect();

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
}

impl Default for QuicStats {
    fn default() -> Self {
        Self::new()
    }
}