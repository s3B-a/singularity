use super::alpn::AlpnProtocol;
use super::error::{ErrorCode, Http2Error, Result};
use super::flow_control::{decode_secure_flow_control, encode_secure_flow_control, FlowControl};
use super::frame::{Frame, FrameFlags, FrameType};
use super::hpack::{decode_secure_hpack_codec, encode_secure_hpack_codec, HpackCodec};
use super::priority::{decode_secure_priority_tree, encode_secure_priority_tree, parse_priority_header, ExtensiblePriority, Priority, PriorityTree};
use super::push::{decode_secure_push_manager, encode_secure_push_manager, PushConfig, PushManager};
use super::scheduler::{decode_secure_priority_scheduler, encode_secure_priority_scheduler, DependencyTreeStats, PriorityScheduler};
use super::settings::{decode_secure_settings, encode_secure_settings, SettingId, Settings};
use super::stream::{decode_secure_http2_stream, encode_secure_http2_stream, Http2Stream, StreamState};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::tcp::TcpStream;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_CONNECTION_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_CONNECTION_BLOB_V1";
const HTTP2_CONNECTION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_CONNECTION_BLOB_BINDING_V1";
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
const MAX_HEADER_BLOCK_SIZE: usize = 1024 * 1024;
const MAX_CONTINUATION_FRAMES: usize = 128;
const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTSTANDING_PINGS: usize = 8;
const DEFAULT_MAX_RESETS_PER_WINDOW: usize = 100;
const DEFAULT_RESET_WINDOW: Duration = Duration::from_secs(1);
const CONNECTION_SPECIFIC_HEADERS: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];
const REQUEST_PSEUDO_HEADERS: &[&str] = &[":method", ":scheme", ":authority", ":path", ":protocol"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp2ConnectionBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub trait Http2Transport: Read + Write + Send {}

impl<T: Read + Write + Send> Http2Transport for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "client" => Some(Role::Client),
            "server" => Some(Role::Server),
            _ => None,
        }
    }

    fn first_stream_id(&self) -> u32 {
        match self {
            Role::Client => 1,
            Role::Server => 2,
        }
    }
}

pub struct Http2Connection {
    stream: Box<dyn Http2Transport>,
    role: Role,
    pub streams: HashMap<u32, Http2Stream>,
    next_stream_id: u32,
    local_settings: Settings,
    remote_settings: Settings,
    connection_flow_control: FlowControl,
    encoder: HpackCodec,
    decoder: HpackCodec,
    priority_tree: PriorityTree,
    last_stream_id: u32,
    highest_peer_stream_id: u32,
    peer_initiated_streams: HashSet<u32>,
    pub goaway_sent: bool,
    pub goaway_received: bool,
    goaway_final_sent: bool,
    local_goaway_last_stream_id: Option<u32>,
    peer_goaway_error: Option<ErrorCode>,
    goaway_unprocessed_streams: Vec<u32>,
    shutdown_ping: Option<[u8; 8]>,
    continuation_state: Option<ContinuationState>,
    scheduler: PriorityScheduler,
    max_frame_size: u32,
    push_manager: PushManager,
    negotiated_protocol: Option<AlpnProtocol>,
    local_settings_sent: bool,
    peer_settings_received: bool,
    pending_settings_acks: VecDeque<Instant>,
    pings_outstanding: HashMap<[u8; 8], Instant>,
    last_ping_rtt: Option<Duration>,
    ack_timeout: Duration,
    keepalive_interval: Option<Duration>,
    last_frame_received_at: Instant,
    recent_resets: VecDeque<Instant>,
    max_resets_per_window: usize,
    reset_window: Duration,
}

#[derive(Debug)]
struct ContinuationState {
    stream_id: u32,
    header_block_fragments: Vec<u8>,
    end_stream: bool,
    is_push_promise: bool,
    parent_stream_id: Option<u32>,
    priority: Option<Priority>,
    promised_stream_id: Option<u32>,
    frame_count: usize,
}

impl ContinuationState {
    fn new(stream_id: u32, end_stream: bool, is_push_promise: bool) -> Self {
        Self {
            stream_id,
            header_block_fragments: Vec::new(),
            end_stream,
            is_push_promise,
            parent_stream_id: None,
            priority: None,
            promised_stream_id: None,
            frame_count: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderBlockKind {
    Request,
    Response,
    Trailers,
}

impl Http2Connection {
    pub fn new(stream: TcpStream) -> Result<Self> {
        Self::with_transport(stream, Role::Client)
    }

    pub fn new_server<T: Http2Transport + 'static>(transport: T) -> Result<Self> {
        Self::with_transport(transport, Role::Server)
    }

    pub fn new_server_with_alpn<T: Http2Transport + 'static>(transport: T, negotiated_protocol: Option<AlpnProtocol>) -> Result<Self> {
        check_alpn(negotiated_protocol)?;
        let mut conn = Self::new_server(transport)?;
        conn.negotiated_protocol = negotiated_protocol;
        
        Ok(conn)
    }

    pub fn with_transport<T: Http2Transport + 'static>(transport: T, role: Role) -> Result<Self> {
        Self::from_boxed_transport(Box::new(transport), role)
    }

    fn from_boxed_transport(stream: Box<dyn Http2Transport>, role: Role) -> Result<Self> {
        let mut local_settings = Settings::local_defaults();
        if role == Role::Server {
            local_settings.set(SettingId::EnablePush, 0).map_err(Http2Error::NotPermitted)?;
        }

        let remote_settings = Settings::default();
        let connection_flow_control = FlowControl::new(remote_settings.initial_window_size());

        Ok(Self {
            stream,
            role,
            streams: HashMap::new(),
            next_stream_id: role.first_stream_id(),
            local_settings: local_settings.clone(),
            remote_settings,
            connection_flow_control,
            encoder: HpackCodec::new(local_settings.header_table_size() as usize),
            decoder: HpackCodec::new(local_settings.header_table_size() as usize),
            priority_tree: PriorityTree::new(),
            last_stream_id: 0,
            highest_peer_stream_id: 0,
            peer_initiated_streams: HashSet::new(),
            goaway_sent: false,
            goaway_received: false,
            goaway_final_sent: false,
            local_goaway_last_stream_id: None,
            peer_goaway_error: None,
            goaway_unprocessed_streams: Vec::new(),
            shutdown_ping: None,
            continuation_state: None,
            scheduler: PriorityScheduler::new(),
            max_frame_size: 16384,
            push_manager: PushManager::with_defaults(),
            negotiated_protocol: None,
            local_settings_sent: false,
            peer_settings_received: false,
            pending_settings_acks: VecDeque::new(),
            pings_outstanding: HashMap::new(),
            last_ping_rtt: None,
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            keepalive_interval: None,
            last_frame_received_at: Instant::now(),
            recent_resets: VecDeque::new(),
            max_resets_per_window: DEFAULT_MAX_RESETS_PER_WINDOW,
            reset_window: DEFAULT_RESET_WINDOW,
        })
    }

    pub fn handshake(&mut self) -> Result<()> {
        self.send_preface()
    }

    pub fn new_with_alpn(stream: TcpStream, negotiated_protocol: Option<AlpnProtocol>) -> Result<Self> {
        check_alpn(negotiated_protocol)?;
        let mut conn = Self::new(stream)?;
        conn.negotiated_protocol = negotiated_protocol;
        
        Ok(conn)
    }

    pub fn handshake_with_alpn(&mut self, negotiated_protocol: Option<AlpnProtocol>) -> Result<()> {
        check_alpn(negotiated_protocol)?;
        if negotiated_protocol.is_some() {
            self.negotiated_protocol = negotiated_protocol;
        }

        self.send_preface()
    }

    pub fn role(&self) -> Role {
        self.role
    }

    fn is_peer_stream_id(&self, stream_id: u32) -> bool {
        stream_id % 2 != self.role.first_stream_id() % 2
    }

    fn initial_settings(&self) -> Vec<(u16, u32)> {
        let mut settings = vec![
            (SettingId::HeaderTableSize as u16, self.local_settings.header_table_size()),
            (SettingId::EnablePush as u16, if self.local_settings.enable_push() { 1 } else { 0 }),
            (SettingId::MaxConcurrentStreams as u16, self.local_settings.max_concurrent_streams()),
            (SettingId::InitialWindowSize as u16, self.local_settings.initial_window_size()),
            (SettingId::MaxFrameSize as u16, self.local_settings.max_frame_size()),
            (SettingId::MaxHeaderListSize as u16, self.local_settings.max_header_list_size()),
        ];
        
        if self.local_settings.enable_connect_protocol() {
            settings.push((SettingId::EnableConnectProtocol as u16, 1));
        }
        
        if self.local_settings.no_rfc7540_priorities() {
            settings.push((SettingId::NoRfc7540Priorities as u16, 1));
        }
        
        settings
    }

    fn send_preface(&mut self) -> Result<()> {
        match self.role {
            Role::Client => self.stream.write_all(CLIENT_PREFACE)?,
            Role::Server => {
                let mut preface = [0u8; CLIENT_PREFACE.len()];
                self.stream.read_exact(&mut preface)?;
                if preface != CLIENT_PREFACE {
                    return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "invalid client connection preface".to_string()));
                }
            }
        }

        Frame::settings(self.initial_settings()).write(&mut self.stream)?;
        self.stream.flush()?;
        self.local_settings_sent = true;
        self.pending_settings_acks.push_back(Instant::now());

        let frame = match Frame::read_limited(&mut self.stream, self.local_settings.max_frame_size()) {
            Ok(frame) => frame,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(self.fail_connection(Http2Error::Protocol(ErrorCode::FrameSizeError, e.to_string())));
            }
            Err(e) => return Err(e.into()),
        };

        if frame.header.frame_type != FrameType::Settings || frame.header.flags.has(FrameFlags::ACK) {
            return Err(self.fail_connection(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "peer connection preface did not start with SETTINGS".to_string(),
            )));
        }

        self.last_frame_received_at = Instant::now();

        self.handle_settings_frame(&frame).map_err(|e| self.fail_connection(e))
    }

    pub fn negotiated_protocol(&self) -> Option<AlpnProtocol> {
        self.negotiated_protocol
    }

    pub fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    pub fn remote_settings(&self) -> &Settings {
        &self.remote_settings
    }

    pub fn set_local_setting(&mut self, id: SettingId, value: u32) -> Result<()> {
        if self.role == Role::Server && id == SettingId::EnablePush && value != 0 {
            return Err(Http2Error::NotPermitted("a server cannot enable push for itself".to_string()));
        }
        
        if self.local_settings_sent {
            let fixed = matches!(id, SettingId::HeaderTableSize | SettingId::InitialWindowSize | SettingId::NoRfc7540Priorities);
            let withdraws_connect = id == SettingId::EnableConnectProtocol && value == 0 && self.local_settings.enable_connect_protocol();
            if fixed || withdraws_connect {
                return Err(Http2Error::NotPermitted(format!("{:?} cannot be changed after the handshake", id)));
            }
        }
        
        self.local_settings.set(id, value).map_err(Http2Error::NotPermitted)?;
        match id {
            SettingId::HeaderTableSize => {
                self.decoder.set_max_dynamic_table_size_limit(value as usize).map_err(Http2Error::NotPermitted)?;
            }
            SettingId::NoRfc7540Priorities => self.scheduler.set_extensible_mode(value == 1),
            _ => {}
        }

        if self.local_settings_sent {
            Frame::settings(vec![(id as u16, value)]).write(&mut self.stream)?;
            self.stream.flush()?;
            self.pending_settings_acks.push_back(Instant::now());
        }

        Ok(())
    }

    pub fn create_stream(&mut self) -> Result<u32> {
        self.open_local_stream(Priority::default())
    }

    pub fn create_stream_with_priority(&mut self, priority: Priority) -> Result<u32> {
        self.open_local_stream(priority)
    }
    
    pub fn create_stream_with_extensible_priority(&mut self, priority: ExtensiblePriority) -> Result<u32> {
        let stream_id = self.open_local_stream(Priority::default())?;
        self.scheduler.update_extensible_priority(stream_id, priority);
        
        Ok(stream_id)
    }

    fn open_local_stream(&mut self, priority: Priority) -> Result<u32> {
        self.ensure_outbound_stream_capacity()?;
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let stream = Http2Stream::new(stream_id, self.remote_settings.initial_window_size());
        self.streams.insert(stream_id, stream);
        self.scheduler.add_stream(stream_id, priority);
        
        Ok(stream_id)
    }

    fn ensure_outbound_stream_capacity(&self) -> Result<()> {
        if self.goaway_sent || self.goaway_received {
            return Err(Http2Error::ConnectionClosed);
        }

        if self.next_stream_id > MAX_STREAM_ID {
            return Err(Http2Error::ConnectionClosed);
        }

        if !self.remote_settings.allows_new_stream(self.active_local_stream_count()) {
            return Err(Http2Error::StreamLimitReached(self.remote_settings.max_concurrent_streams()));
        }

        Ok(())
    }

    pub fn can_open_stream(&self) -> bool {
        self.ensure_outbound_stream_capacity().is_ok()
    }

    pub fn peer_max_concurrent_streams(&self) -> u32 {
        self.remote_settings.max_concurrent_streams()
    }

    fn active_local_stream_count(&self) -> usize {
        self.streams.iter().filter(|(id, stream)| {
            !self.peer_initiated_streams.contains(id) && !stream.is_closed()
        }).count()
    }

    fn active_peer_stream_count(&self) -> usize {
        self.streams.iter().filter(|(id, stream)| {
            self.peer_initiated_streams.contains(id) && !matches!(stream.state(), StreamState::Idle | StreamState::ReservedRemote | StreamState::Closed)
        }).count()
    }

    pub fn update_stream_priority(&mut self, stream_id: u32, priority: Priority) -> Result<()> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.set_priority(priority.clone());
            self.scheduler.update_priority(stream_id, priority);
            Ok(())
        } else {
            Err(Http2Error::StreamNotFound(stream_id))
        }
    }

    pub fn set_extensible_priority(&mut self, stream_id: u32, priority: ExtensiblePriority) -> Result<()> {
        let stream = self.streams.get(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
        let request_sent = stream.state() != StreamState::Idle;
        let closed = stream.is_closed();
        self.scheduler.update_extensible_priority(stream_id, priority);
        if request_sent && !closed {
            self.send_priority_update(stream_id, priority)?;
        }
        
        Ok(())
    }

    pub fn send_priority_update(&mut self, stream_id: u32, priority: ExtensiblePriority) -> Result<()> {
        Frame::priority_update(stream_id, priority).write(&mut self.stream)?;
        self.stream.flush()?;
        
        Ok(())
    }

    pub fn get_extensible_priority(&self, stream_id: u32) -> ExtensiblePriority {
        self.scheduler.get_extensible_priority(stream_id)
    }

    pub fn send_request(&mut self, stream_id: u32, mut headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> Result<()> {
        let body = body.filter(|data| !data.is_empty());
        if headers.iter().any(|(name, _)| name == ":protocol") {
            self.ensure_extended_connect_allowed()?;
        }
        
        let has_priority_header = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("priority"));
        if !self.peer_initiated_streams.contains(&stream_id) {
            match self.scheduler.explicit_extensible_priority(stream_id) {
                Some(priority) if !has_priority_header && !priority.is_default() => {
                    headers.push(("priority".to_string(), priority.to_header_value()));
                }
                None if has_priority_header => {
                    let value = headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("priority")).map(|(_, value)| value.clone()).unwrap_or_default();
                    self.scheduler.update_extensible_priority(stream_id, parse_priority_header(&value));
                }
                _ => {}
            }
        }
        
        self.send_header_block(stream_id, headers, body.is_none())?;
        if let Some(body_data) = body {
            self.send_data(stream_id, &body_data, true)?;
        }

        self.stream.flush()?;
        Ok(())
    }

    pub fn peer_supports_extended_connect(&self) -> bool {
        self.remote_settings.enable_connect_protocol()
    }

    fn ensure_extended_connect_allowed(&self) -> Result<()> {
        if !self.peer_supports_extended_connect() {
            return Err(Http2Error::NotPermitted(
                "peer did not enable SETTINGS_ENABLE_CONNECT_PROTOCOL".to_string(),
            ));
        }

        Ok(())
    }

    pub fn send_extended_connect(&mut self, stream_id: u32, protocol: &str, scheme: &str, authority: &str, path: &str, extra_headers: Vec<(String, String)>) -> Result<()> {
        self.ensure_extended_connect_allowed()?;
        let mut headers: Vec<(String, String)> = [
            (":method", "CONNECT"),
            (":protocol", protocol),
            (":scheme", scheme),
            (":authority", authority),
            (":path", path),
        ].into_iter().map(|(name, value)| (name.to_string(), value.to_string())).collect();
        headers.extend(extra_headers.into_iter().filter(|(name, _)| !name.starts_with(':')));

        self.send_header_block(stream_id, headers, false)?;
        self.stream.flush()?;
        Ok(())
    }

    fn send_header_block(&mut self, stream_id: u32, headers: Vec<(String, String)>, end_stream: bool) -> Result<()> {
        {
            let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
            match stream.state() {
                StreamState::Idle | StreamState::ReservedLocal => stream.send_headers()?,
                StreamState::Open | StreamState::HalfClosedRemote => {}
                _ => return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "stream is closed for sending".to_string())),
            }
            
            stream.set_request_headers(headers.clone());
        }

        let encoded_headers = self.encoder.encode_list(&headers);
        self.send_headers_with_continuation(stream_id, encoded_headers, end_stream)?;
        if end_stream {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.send_end_stream()?;
            }
        }

        Ok(())
    }

    pub fn send_pending_data(&mut self) -> Result<usize> {
        let mut total_sent = 0;
        while self.scheduler.has_ready_streams() {
            let stream_id = match self.scheduler.schedule_next() {
                Some(id) => id,
                None => break,
            };
            
            if self.connection_flow_control.window_size() <= 0 {
                break;
            }
            
            let stream = match self.streams.get_mut(&stream_id) {
                Some(s) => s,
                None => {
                    self.scheduler.remove_stream(stream_id);
                    continue;
                }
            };
            
            if stream.send_buffer_len() == 0 {
                self.scheduler.mark_blocked(stream_id);
                continue;
            }
            
            let stream_window = stream.flow_control().window_size();
            if stream_window <= 0 {
                self.scheduler.mark_blocked(stream_id);
                continue;
            }
            
            let conn_window = self.connection_flow_control.window_size() as usize;
            let max_send = conn_window.min(stream_window as usize).min(self.max_frame_size as usize);
            
            let data = stream.get_send_data(max_send);
            if data.is_empty() {
                self.scheduler.mark_blocked(stream_id);
                continue;
            }
            
            let data_len = data.len();
            let ends_stream = stream.is_send_complete() && stream.send_buffer_len() == 0;
            let flags = if ends_stream {
                FrameFlags::END_STREAM
            } else {
                0
            };

            let frame = Frame::new(FrameType::Data, flags, stream_id, data);
            frame.write(&mut self.stream)?;
            
            self.connection_flow_control.consume(data_len)?;
            stream.flow_control_mut().consume(data_len)?;
            if ends_stream {
                stream.send_end_stream()?;
            }
            
            self.scheduler.bytes_sent(stream_id, data_len);
            total_sent += data_len;
            if stream.send_buffer_len() > 0 {
                self.scheduler.mark_ready(stream_id, stream.send_buffer_len());
            } else {
                self.scheduler.mark_blocked(stream_id);
            }
        }
        
        Ok(total_sent)
    }

    fn send_headers_with_continuation(&mut self, stream_id: u32, mut headers_data: Vec<u8>, end_stream: bool) -> Result<()> {
        let max_frame_size = self.remote_settings.max_frame_size() as usize;
        if headers_data.len() <= max_frame_size {
            let frame = Frame::headers(stream_id, headers_data, true, end_stream);
            frame.write(&mut self.stream)?;
        } else {
            let first_chunk: Vec<u8> = headers_data.drain(..max_frame_size).collect();
            let frame = Frame::headers(stream_id, first_chunk, false, end_stream);
            frame.write(&mut self.stream)?;
            while !headers_data.is_empty() {
                let chunk_size = headers_data.len().min(max_frame_size);
                let chunk: Vec<u8> = headers_data.drain(..chunk_size).collect();
                let is_last = headers_data.is_empty();
                
                let continuation = Frame::continuation(stream_id, chunk, is_last);
                continuation.write(&mut self.stream)?;
            }
        }
        
        Ok(())
    }

    pub fn send_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> Result<()> {
        let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
        if !stream.can_send() {
            return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "stream is closed for sending".to_string()));
        }

        stream.queue_send_data(data.to_vec())?;
        if end_stream {
            stream.mark_send_complete();
        }
        
        self.scheduler.mark_ready(stream_id, stream.send_buffer_len());
        self.send_pending_data()?;
        
        Ok(())
    }

    pub fn receive_frames(&mut self) -> Result<()> {
        loop {
            match self.receive_frame() {
                Ok(()) => {}
                Err(Http2Error::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        
        self.poll_keepalive()
    }
    
    pub fn receive_frame(&mut self) -> Result<()> {
        let frame = match Frame::read_limited(&mut self.stream, self.local_settings.max_frame_size()) {
            Ok(f) => f,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                self.poll_keepalive()?;
                return Err(e.into());
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(self.fail_connection(Http2Error::Protocol(ErrorCode::FrameSizeError, e.to_string())));
            }
            Err(e) => return Err(e.into()),
        };

        self.last_frame_received_at = Instant::now();
        self.dispatch_frame(frame)
    }
    
    fn dispatch_frame(&mut self, frame: Frame) -> Result<()> {
        match self.handle_frame(frame) {
            Ok(()) => Ok(()),
            Err(Http2Error::Stream(stream_id, code, _)) => {
                self.reset_stream_on_error(stream_id, code).map_err(|e| self.fail_connection(e))
            }
            Err(Http2Error::StreamNotFound(stream_id)) => {
                self.reset_stream_on_error(stream_id, ErrorCode::StreamClosed).map_err(|e| self.fail_connection(e))
            }
            Err(err) => Err(self.fail_connection(err)),
        }
    }
    
    fn reset_stream_on_error(&mut self, stream_id: u32, code: ErrorCode) -> Result<()> {
        Frame::rst_stream(stream_id, code as u32).write(&mut self.stream)?;
        self.stream.flush()?;
        self.close_reset_stream(stream_id);
        
        self.record_peer_reset()
    }
    
    fn close_reset_stream(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset();
        }
        
        self.scheduler.mark_closed(stream_id);
        if self.peer_initiated_streams.remove(&stream_id) {
            self.streams.remove(&stream_id);
        }
    }
    
    fn record_peer_reset(&mut self) -> Result<()> {
        let now = Instant::now();
        self.recent_resets.push_back(now);
        while self.recent_resets.front().is_some_and(|time| now.duration_since(*time) > self.reset_window) {
            self.recent_resets.pop_front();
        }
        
        if self.recent_resets.len() > self.max_resets_per_window {
            return Err(Http2Error::Protocol(ErrorCode::EnhanceYourCalm, "excessive stream resets".to_string()));
        }
        
        Ok(())
    }

    pub fn set_reset_rate_limit(&mut self, max_resets: usize, window: Duration) {
        self.max_resets_per_window = max_resets;
        self.reset_window = window;
    }

    fn fail_connection(&mut self, err: Http2Error) -> Http2Error {
        if let Http2Error::Protocol(code, ref msg) = err {
            if !self.goaway_final_sent {
                let _ = self.send_goaway(code, msg.as_bytes().to_vec());
            }
        }

        err
    }

    pub fn close_stream(&mut self, stream_id: u32) -> Result<()> {
        let active = self.streams.get(&stream_id).is_some_and(|stream| {
            !matches!(stream.state(), StreamState::Idle | StreamState::Closed)
        });

        if active {
            Frame::rst_stream(stream_id, ErrorCode::Cancel as u32).write(&mut self.stream)?;
            self.stream.flush()?;
        }

        self.close_reset_stream(stream_id);
        Ok(())
    }

    pub fn get_scheduler_stats(&self) -> DependencyTreeStats {
        self.scheduler.get_tree_stats()
    }

    pub fn get_stream_priority(&self, stream_id: u32) -> Option<Priority> {
        self.scheduler.get_priority(stream_id)
    }

    fn is_idle_stream(&self, stream_id: u32) -> bool {
        if self.streams.contains_key(&stream_id) {
            return false;
        }

        if self.is_peer_stream_id(stream_id) {
            stream_id > self.highest_peer_stream_id
        } else {
            stream_id >= self.next_stream_id
        }
    }

    fn is_beyond_local_goaway(&self, stream_id: u32) -> bool {
        self.local_goaway_last_stream_id.is_some_and(|last| stream_id > last) && !self.streams.contains_key(&stream_id)
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<()> {
        if let Some(ref state) = self.continuation_state {
            if frame.header.frame_type != FrameType::Continuation {
                return Err(Http2Error::Protocol(
                    ErrorCode::ProtocolError,
                    "Expected CONTINUATION frame".to_string(),
                ));
            }

            if frame.header.stream_id != state.stream_id {
                return Err(Http2Error::Protocol(
                    ErrorCode::ProtocolError,
                    format!(
                        "CONTINUATION on wrong stream: expected {}, got {}",
                        state.stream_id, frame.header.stream_id
                    ),
                ));
            }
        } else if frame.header.frame_type == FrameType::Continuation {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Unexpected CONTINUATION frame".to_string(),
            ));
        }

        match frame.header.frame_type {
            FrameType::Data | FrameType::Headers | FrameType::Priority |
            FrameType::RstStream | FrameType::PushPromise | FrameType::Continuation => {
                if frame.header.stream_id == 0 {
                    return Err(Http2Error::Protocol(
                        ErrorCode::ProtocolError,
                        format!("{:?} frame on stream 0", frame.header.frame_type),
                    ));
                }
            }
            _ => {}
        }

        match frame.header.frame_type {
            FrameType::Data => self.handle_data_frame(&frame),
            FrameType::Headers => self.handle_headers_frame(&frame),
            FrameType::Priority => self.handle_priority_frame(&frame),
            FrameType::RstStream => self.handle_rst_stream_frame(&frame),
            FrameType::Settings => self.handle_settings_frame(&frame),
            FrameType::PushPromise => self.handle_push_promise_frame(&frame),
            FrameType::Ping => self.handle_ping_frame(&frame),
            FrameType::GoAway => self.handle_goaway_frame(&frame),
            FrameType::WindowUpdate => self.handle_window_update_frame(&frame),
            FrameType::Continuation => self.handle_continuation_frame(&frame),
            FrameType::PriorityUpdate => self.handle_priority_update_frame(&frame),
            FrameType::Unknown => Ok(()),
        }
    }

    fn handle_data_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;
        let data = strip_padding(frame)?;
        let flow_len = frame.payload.len() as u32;
        if flow_len > 0 {
            Frame::window_update(0, flow_len).write(&mut self.stream)?;
            self.stream.flush()?;
        }
        
        if self.is_idle_stream(stream_id) {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "DATA on an idle stream".to_string()));
        }
        
        if self.is_beyond_local_goaway(stream_id) {
            return Ok(());
        }
        
        let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::Stream(
            stream_id,
            ErrorCode::StreamClosed,
            "DATA received for a closed stream".to_string(),
        ))?;
        
        if !stream.can_receive() {
            return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "DATA received on a stream closed for receiving".to_string()));
        }

        stream.receive_data(data.to_vec()).map_err(|e| e.into_stream_error(stream_id))?;
        if self.push_manager.get_push(stream_id).is_some() {
            self.push_manager.add_push_data(stream_id, data.to_vec()).map_err(|e| e.into_stream_error(stream_id))?;
        }

        let end_stream = frame.header.flags.has(FrameFlags::END_STREAM);
        if end_stream {
            stream.receive_end_stream().map_err(|e| e.into_stream_error(stream_id))?;
            if self.push_manager.get_push(stream_id).is_some() {
                self.push_manager.complete_push(stream_id).map_err(|e| e.into_stream_error(stream_id))?;
            }
        } else if flow_len > 0 {
            Frame::window_update(stream_id, flow_len).write(&mut self.stream)?;
            self.stream.flush()?;
        }

        Ok(())
    }

    fn handle_continuation_frame(&mut self, frame: &Frame) -> Result<()> {
        let mut state = self.continuation_state.take().ok_or_else(|| {
            Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "CONTINUATION without HEADERS/PUSH_PROMISE".to_string(),
            )
        })?;

        state.frame_count += 1;
        if state.frame_count > MAX_CONTINUATION_FRAMES {
            return Err(Http2Error::Protocol(ErrorCode::EnhanceYourCalm, "too many CONTINUATION frames".to_string()));
        }

        if state.header_block_fragments.len().saturating_add(frame.payload.len()) > MAX_HEADER_BLOCK_SIZE {
            return Err(Http2Error::Protocol(ErrorCode::EnhanceYourCalm, "header block is too large".to_string()));
        }

        state.header_block_fragments.extend_from_slice(&frame.payload);
        if frame.header.flags.has(FrameFlags::END_HEADERS) {
            self.complete_header_block(state)
        } else {
            self.continuation_state = Some(state);
            Ok(())
        }
    }
    
    fn handle_headers_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;
        let mut header_block = strip_padding(frame)?;
        let priority = if frame.header.flags.has(FrameFlags::PRIORITY) {
            if header_block.len() < 5 {
                return Err(Http2Error::Protocol(ErrorCode::FrameSizeError, "missing HEADERS priority fields".to_string()));
            }
            let priority = Priority::parse(header_block);
            header_block = &header_block[5..];
            Some(priority)
        } else {
            None
        };
        
        if header_block.len() > MAX_HEADER_BLOCK_SIZE {
            return Err(Http2Error::Protocol(ErrorCode::EnhanceYourCalm, "header block is too large".to_string()));
        }
        
        let mut state = ContinuationState::new(stream_id, frame.header.flags.has(FrameFlags::END_STREAM), false);
        state.priority = priority;
        state.header_block_fragments.extend_from_slice(header_block);
        if frame.header.flags.has(FrameFlags::END_HEADERS) {
            self.complete_header_block(state)
        } else {
            self.continuation_state = Some(state);
            Ok(())
        }
    }

    fn complete_header_block(&mut self, state: ContinuationState) -> Result<()> {
        let headers_map = self.decoder.decode(&state.header_block_fragments).map_err(|e| {
            Http2Error::Protocol(
                ErrorCode::CompressionError,
                format!("HPACK decode error: {}", e),
            )
        })?;

        let headers: Vec<(String, String)> = headers_map.into_iter().collect();
        if state.is_push_promise {
            let parent_id = state.parent_stream_id.unwrap_or(state.stream_id);
            let promised_id = state.promised_stream_id.unwrap_or(0);
            return self.process_push_promise(parent_id, promised_id, headers);
        }
        
        if self.push_manager.get_push(state.stream_id).is_some() {
            self.push_manager.add_push_headers(state.stream_id, headers.clone()).map_err(|e| e.into_stream_error(state.stream_id))?;
        }

        self.process_received_headers(state.stream_id, headers, state.end_stream, state.priority)
    }
    
    fn process_received_headers(&mut self, stream_id: u32, headers: Vec<(String, String)>, end_stream: bool, priority: Option<Priority>) -> Result<()> {
        let is_new = !self.streams.contains_key(&stream_id);
        if is_new {
            if self.role == Role::Client || !self.is_peer_stream_id(stream_id) {
                if self.is_idle_stream(stream_id) {
                    return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "HEADERS opened a stream the peer may not open".to_string()));
                }

                return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "HEADERS on a closed stream".to_string()));
            }
            
            if stream_id <= self.highest_peer_stream_id {
                return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "HEADERS on a closed stream".to_string()));
            }
            
            self.highest_peer_stream_id = stream_id;
            if self.is_beyond_local_goaway(stream_id) {
                return Ok(());
            }
            
            if !self.local_settings.allows_new_stream(self.active_peer_stream_count()) {
                return Err(Http2Error::Stream(stream_id, ErrorCode::RefusedStream, "MAX_CONCURRENT_STREAMS exceeded".to_string()));
            }
        }
        
        let header_size: usize = headers.iter().map(|(name, value)| {
            name.len() + value.len() + 32
        }).sum();

        if header_size > self.local_settings.max_header_list_size() as usize {
            return Err(Http2Error::Stream(
                stream_id,
                ErrorCode::ProtocolError,
                "Header list size exceeds maximum".to_string(),
            ));
        }

        let kind = validate_header_block(&headers, self.local_settings.enable_connect_protocol())
            .map_err(|msg| Http2Error::Stream(stream_id, ErrorCode::ProtocolError, msg))?;
        let headers_received = self.streams.get(&stream_id).is_some_and(|stream| stream.headers_received);
        match kind {
            HeaderBlockKind::Response if is_new => {
                return Err(Http2Error::Stream(stream_id, ErrorCode::ProtocolError, "a new stream must start with a request".to_string()));
            }
            HeaderBlockKind::Trailers if is_new || !headers_received => {
                return Err(Http2Error::Stream(stream_id, ErrorCode::ProtocolError, "header block is missing pseudo-header fields".to_string()));
            }
            HeaderBlockKind::Trailers if !end_stream => {
                return Err(Http2Error::Stream(stream_id, ErrorCode::ProtocolError, "trailers must end the stream".to_string()));
            }
            _ => {}
        }
        
        let priority = priority.filter(|_| !self.local_settings.no_rfc7540_priorities());
        if priority.as_ref().is_some_and(|p| p.stream_dependency == stream_id) {
            return Err(Http2Error::Stream(stream_id, ErrorCode::ProtocolError, "stream cannot depend on itself".to_string()));
        }
        
        if is_new {
            let stream = Http2Stream::new(stream_id, self.remote_settings.initial_window_size());
            self.streams.insert(stream_id, stream);
            self.peer_initiated_streams.insert(stream_id);
            self.scheduler.add_stream(stream_id, priority.clone().unwrap_or_default());
        } else if let Some(priority) = priority.clone() {
            self.scheduler.update_priority(stream_id, priority);
        }
        
        if let Some(priority) = priority {
            self.priority_tree.set_priority(stream_id, priority);
        }
        
        if kind == HeaderBlockKind::Request && self.scheduler.explicit_extensible_priority(stream_id).is_none() {
            if let Some((_, value)) = headers.iter().find(|(name, _)| name == "priority") {
                self.scheduler.update_extensible_priority(stream_id, parse_priority_header(value));
            }
        }
        
        let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
        match stream.state() {
            StreamState::Idle | StreamState::ReservedRemote => {
                stream.receive_headers().map_err(|e| e.into_stream_error(stream_id))?;
            }
            StreamState::Open | StreamState::HalfClosedLocal => {}
            _ => {
                return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed, "HEADERS on a stream closed for receiving".to_string()));
            }
        }
        
        if kind == HeaderBlockKind::Trailers {
            stream.add_trailers(headers);
        } else {
            stream.add_response_headers(headers);
        }
        
        if end_stream {
            stream.receive_end_stream().map_err(|e| e.into_stream_error(stream_id))?;
        }

        Ok(())
    }

    fn handle_priority_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;
        if !self.streams.contains_key(&stream_id) {
            return Ok(());
        }

        if frame.payload.len() != 5 {
            return Err(Http2Error::Stream(
                stream_id,
                ErrorCode::FrameSizeError,
                "Invalid PRIORITY frame size".to_string(),
            ));
        }

        if self.local_settings.no_rfc7540_priorities() {
            return Ok(());
        }
        
        let priority = Priority::parse(&frame.payload);
        if priority.stream_dependency == stream_id {
            return Err(Http2Error::Stream(stream_id, ErrorCode::ProtocolError, "stream cannot depend on itself".to_string()));
        }
        
        self.scheduler.update_priority(stream_id, priority.clone());
        self.priority_tree.set_priority(stream_id, priority);
        Ok(())
    }

    fn handle_rst_stream_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() != 4 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid RST_STREAM frame size".to_string(),
            ));
        }

        let stream_id = frame.header.stream_id;
        if self.is_idle_stream(stream_id) {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "RST_STREAM on an idle stream".to_string()));
        }

        let peer_side = self.peer_initiated_streams.contains(&stream_id) || !self.streams.contains_key(&stream_id);
        self.close_reset_stream(stream_id);
        if peer_side {
            self.record_peer_reset()?;
        }

        Ok(())
    }

    fn handle_settings_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "SETTINGS frame on non-zero stream".to_string(),
            ));
        }

        if frame.header.flags.has(FrameFlags::ACK) {
            if !frame.payload.is_empty() {
                return Err(Http2Error::Protocol(ErrorCode::FrameSizeError, "SETTINGS ACK must have an empty payload".to_string()));
            }

            self.pending_settings_acks.pop_front();
            return Ok(());
        }

        if frame.payload.len() % 6 != 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid SETTINGS frame size".to_string(),
            ));
        }

        if self.role == Role::Client {
            let enables_push = frame.payload.chunks_exact(6).any(|entry| {
                u16::from_be_bytes([entry[0], entry[1]]) == SettingId::EnablePush as u16 && entry[2..] != [0, 0, 0, 0]
            });
            if enables_push {
                return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "a server cannot set SETTINGS_ENABLE_PUSH to 1".to_string()));
            }
        }

        let old_initial_window = self.remote_settings.initial_window_size();
        let old_table_size = self.remote_settings.header_table_size();
        let is_first = !self.peer_settings_received;
        self.remote_settings.apply_update(&frame.payload, is_first).map_err(|(id, msg)| {
            let code = if id == SettingId::InitialWindowSize { ErrorCode::FlowControlError } else { ErrorCode::ProtocolError };
            Http2Error::Protocol(code, msg)
        })?;
        self.peer_settings_received = true;
        self.max_frame_size = self.remote_settings.max_frame_size();

        let new_table_size = self.remote_settings.header_table_size();
        if new_table_size != old_table_size {
            self.encoder.set_max_dynamic_table_size_limit(new_table_size as usize)
                .map_err(|e| Http2Error::Protocol(ErrorCode::CompressionError, e))?;
            self.encoder.set_max_dynamic_table_size(new_table_size as usize)
                .map_err(|e| Http2Error::Protocol(ErrorCode::CompressionError, e))?;
        }
        
        let new_initial_window = self.remote_settings.initial_window_size();
        if new_initial_window != old_initial_window {
            for stream in self.streams.values_mut() {
                stream.flow_control_mut().update_initial_window_size(new_initial_window)?;
            }
        }

        Frame::settings_ack().write(&mut self.stream)?;
        self.stream.flush()?;

        Ok(())
    }

    pub fn with_push_config(stream: TcpStream, push_config: PushConfig) -> Result<Self> {
        let mut conn = Self::new(stream)?;
        conn.push_manager = PushManager::new(push_config);
        Ok(conn)
    }

    pub fn set_origin(&mut self, origin: String) {
        self.push_manager.set_origin(origin);
    }

    pub fn set_push_enabled(&mut self, enabled: bool) {
        self.push_manager.set_enabled(enabled);
    }

    pub fn push_manager(&self) -> &PushManager {
        &self.push_manager
    }

    pub fn push_manager_mut(&mut self) -> &mut PushManager {
        &mut self.push_manager
    }

    pub fn try_use_cached_push(&mut self, url: &str, method: &str) -> Option<Vec<u8>> {
        self.push_manager
            .find_cached_push(url, method)
            .map(|resource| resource.body.clone())
    }

    fn handle_push_promise_frame(&mut self, frame: &Frame) -> Result<()> {
        if self.role == Role::Server {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "a client cannot send PUSH_PROMISE".to_string()));
        }
        
        if !self.local_settings.enable_push() {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "PUSH_PROMISE received while push is disabled".to_string()));
        }
        
        let parent_stream_id = frame.header.stream_id;
        let parent_open = self.streams.get(&parent_stream_id).is_some_and(|stream| {
            matches!(stream.state(), StreamState::Open | StreamState::HalfClosedLocal)
        });

        if !parent_open {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "PUSH_PROMISE on a stream that is not open".to_string()));
        }
        
        let payload = strip_padding(frame)?;
        if payload.len() < 4 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid PUSH_PROMISE frame size".to_string(),
            ));
        }

        let promised_stream_id = u32::from_be_bytes([
            payload[0],
            payload[1],
            payload[2],
            payload[3],
        ]) & MAX_STREAM_ID;
        
        if promised_stream_id == 0 || !self.is_peer_stream_id(promised_stream_id) || promised_stream_id <= self.highest_peer_stream_id || self.streams.contains_key(&promised_stream_id) {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "invalid promised stream ID".to_string()));
        }
        
        let header_block = &payload[4..];
        if header_block.len() > MAX_HEADER_BLOCK_SIZE {
            return Err(Http2Error::Protocol(ErrorCode::EnhanceYourCalm, "header block is too large".to_string()));
        }
        
        self.highest_peer_stream_id = promised_stream_id;
        let mut state = ContinuationState::new(parent_stream_id, false, true);
        state.parent_stream_id = Some(parent_stream_id);
        state.promised_stream_id = Some(promised_stream_id);
        state.header_block_fragments.extend_from_slice(header_block);
        if frame.header.flags.has(FrameFlags::END_HEADERS) {
            self.complete_header_block(state)
        } else {
            self.continuation_state = Some(state);
            Ok(())
        }
    }

    fn process_push_promise(&mut self, parent_stream_id: u32, promised_stream_id: u32, headers: Vec<(String, String)>) -> Result<()> {
        let accept = !self.goaway_sent && self.push_manager.handle_push_promise(parent_stream_id, promised_stream_id, headers)?;
        if !accept {
            let frame = Frame::rst_stream(promised_stream_id, ErrorCode::Cancel as u32);
            frame.write(&mut self.stream)?;
            self.stream.flush()?;
            return Ok(());
        }

        let mut stream = Http2Stream::new(promised_stream_id, self.remote_settings.initial_window_size());
        stream.reserve_remote()?;
        self.streams.insert(promised_stream_id, stream);
        self.peer_initiated_streams.insert(promised_stream_id);
        self.scheduler.add_stream(promised_stream_id, Priority::default());

        Ok(())
    }

    pub fn cleanup_pushes(&mut self) {
        self.push_manager.cleanup();
    }

    pub fn push_stats(&self) -> super::push::PushStats {
        self.push_manager.stats()
    }

    fn handle_ping_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "PING frame on non-zero stream".to_string(),
            ));
        }

        if frame.payload.len() != 8 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid PING frame size".to_string(),
            ));
        }

        let mut data = [0u8; 8];
        data.copy_from_slice(&frame.payload);
        if frame.header.flags.has(FrameFlags::ACK) {
            if let Some(sent_at) = self.pings_outstanding.remove(&data) {
                self.last_ping_rtt = Some(sent_at.elapsed());
            }
        } else {
            Frame::ping(data, true).write(&mut self.stream)?;
            self.stream.flush()?;
        }

        Ok(())
    }

    fn handle_goaway_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "GOAWAY frame on non-zero stream".to_string(),
            ));
        }

        if frame.payload.len() < 8 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid GOAWAY frame size".to_string(),
            ));
        }

        let last_stream_id = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & MAX_STREAM_ID;

        let error_code = u32::from_be_bytes([
            frame.payload[4],
            frame.payload[5],
            frame.payload[6],
            frame.payload[7],
        ]);

        let last_stream_id = if self.goaway_received { last_stream_id.min(self.last_stream_id) } else { last_stream_id };
        self.last_stream_id = last_stream_id;
        self.goaway_received = true;
        self.peer_goaway_error = Some(ErrorCode::from_u32(error_code));
        
        let mut unprocessed: Vec<u32> = self.streams.keys().filter(|&&id| {
            id > last_stream_id && !self.peer_initiated_streams.contains(&id)
        }).copied().collect();
        unprocessed.sort_unstable();

        for stream_id in unprocessed {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                if !stream.is_closed() {
                    stream.reset();
                    if !self.goaway_unprocessed_streams.contains(&stream_id) {
                        self.goaway_unprocessed_streams.push(stream_id);
                    }
                }
            }

            self.scheduler.mark_closed(stream_id);
        }

        Ok(())
    }

    fn handle_window_update_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() != 4 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid WINDOW_UPDATE frame size".to_string(),
            ));
        }

        let increment = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & 0x7FFFFFFF;

        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            self.connection_flow_control.increase(increment)?;
            let ready: Vec<(u32, usize)> = self.streams.iter().filter(|(_, stream)| {
                stream.send_buffer_len() > 0 && stream.flow_control().window_size() > 0
            }).map(|(&id, stream)| (id, stream.send_buffer_len())).collect();

            for (id, pending) in ready {
                self.scheduler.mark_ready(id, pending);
            }
        } else if self.is_idle_stream(stream_id) {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "WINDOW_UPDATE on an idle stream".to_string()));
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.flow_control_mut().increase(increment).map_err(|e| e.into_stream_error(stream_id))?;
            if stream.send_buffer_len() > 0 && stream.flow_control().window_size() > 0 {
                self.scheduler.mark_ready(stream_id, stream.send_buffer_len());
            }
        }
        
        if self.scheduler.has_ready_streams() {
            self.send_pending_data()?;
        }

        Ok(())
    }

    fn handle_priority_update_frame(&mut self, frame: &Frame) -> Result<()> {
        if self.role == Role::Client {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "a server cannot send PRIORITY_UPDATE".to_string()));
        }
        
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "PRIORITY_UPDATE must be sent on stream 0".to_string()));
        }
        
        if frame.payload.len() < 4 {
            return Err(Http2Error::Protocol(ErrorCode::FrameSizeError, "PRIORITY_UPDATE frame is too short".to_string()));
        }

        let stream_id = u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & MAX_STREAM_ID;
        if stream_id == 0 {
            return Err(Http2Error::Protocol(ErrorCode::ProtocolError, "PRIORITY_UPDATE cannot target stream 0".to_string()));
        }
        
        let Ok(value) = std::str::from_utf8(&frame.payload[4..]) else {
            return Ok(());
        };
        
        let open = self.streams.get(&stream_id).is_some_and(|stream| !stream.is_closed());
        if open || self.is_idle_stream(stream_id) {
            self.scheduler.update_extensible_priority(stream_id, parse_priority_header(value));
        }

        Ok(())
    }

    pub fn get_stream(&self, stream_id: u32) -> Option<&Http2Stream> {
        self.streams.get(&stream_id)
    }

    pub fn get_stream_mut(&mut self, stream_id: u32) -> Option<&mut Http2Stream> {
        self.streams.get_mut(&stream_id)
    }

    fn send_goaway(&mut self, code: ErrorCode, debug_data: Vec<u8>) -> Result<()> {
        let last_stream_id = self.highest_peer_stream_id;
        Frame::goaway(last_stream_id, code as u32, debug_data).write(&mut self.stream)?;
        self.stream.flush()?;
        self.goaway_sent = true;
        self.goaway_final_sent = true;
        self.local_goaway_last_stream_id = Some(last_stream_id);
        Ok(())
    }
    
    pub fn begin_graceful_shutdown(&mut self) -> Result<()> {
        if self.goaway_sent {
            return Ok(());
        }
        
        Frame::goaway(MAX_STREAM_ID, ErrorCode::NoError as u32, Vec::new()).write(&mut self.stream)?;
        self.goaway_sent = true;
        self.shutdown_ping = Some(self.send_ping()?);
        Ok(())
    }

    pub fn graceful_shutdown_ready(&self) -> bool {
        self.goaway_sent && self.shutdown_ping.is_some_and(|token| !self.pings_outstanding.contains_key(&token))
    }

    pub fn close(&mut self) -> Result<()> {
        if self.goaway_final_sent {
            return Ok(());
        }

        self.send_goaway(ErrorCode::NoError, Vec::new())
    }

    pub fn close_with_error(&mut self, code: ErrorCode, debug_data: &[u8]) -> Result<()> {
        if self.goaway_final_sent {
            return Ok(());
        }

        self.send_goaway(code, debug_data.to_vec())
    }

    pub fn active_stream_count(&self) -> usize {
        self.streams.values().filter(|stream| !stream.is_closed()).count()
    }

    pub fn peer_goaway_last_stream_id(&self) -> Option<u32> {
        self.goaway_received.then_some(self.last_stream_id)
    }

    pub fn peer_goaway_error(&self) -> Option<ErrorCode> {
        self.peer_goaway_error
    }

    pub fn goaway_unprocessed_streams(&self) -> &[u32] {
        &self.goaway_unprocessed_streams
    }

    pub fn send_ping(&mut self) -> Result<[u8; 8]> {
        if self.pings_outstanding.len() >= MAX_OUTSTANDING_PINGS {
            return Err(Http2Error::NotPermitted("too many unacknowledged PINGs".to_string()));
        }

        let mut token = [0u8; 8];
        if random::fill_random(&mut token).is_err() {
            token = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64).to_be_bytes();
        }

        Frame::ping(token, false).write(&mut self.stream)?;
        self.stream.flush()?;
        self.pings_outstanding.insert(token, Instant::now());
        Ok(token)
    }

    pub fn check_liveness(&mut self) -> Result<()> {
        let now = Instant::now();
        if self.pending_settings_acks.front().is_some_and(|sent| now.duration_since(*sent) > self.ack_timeout) {
            return Err(self.fail_connection(Http2Error::Protocol(
                ErrorCode::SettingsTimeout,
                "SETTINGS acknowledgement timeout".to_string(),
            )));
        }

        if self.pings_outstanding.values().any(|sent| now.duration_since(*sent) > self.ack_timeout) {
            return Err(Http2Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "PING acknowledgement timeout: peer is unresponsive",
            )));
        }

        Ok(())
    }

    pub fn poll_keepalive(&mut self) -> Result<()> {
        self.check_liveness()?;
        if let Some(interval) = self.keepalive_interval {
            if self.pings_outstanding.is_empty() && self.last_frame_received_at.elapsed() >= interval {
                self.send_ping()?;
            }
        }

        Ok(())
    }

    pub fn last_ping_rtt(&self) -> Option<Duration> {
        self.last_ping_rtt
    }

    pub fn set_ack_timeout(&mut self, timeout: Duration) {
        self.ack_timeout = timeout;
    }

    pub fn set_keepalive_interval(&mut self, interval: Option<Duration>) {
        self.keepalive_interval = interval;
    }

    pub fn has_pending_continuation(&self) -> bool {
        self.continuation_state.is_some()
    }

    pub fn pending_continuation_stream(&self) -> Option<u32> {
        self.continuation_state.as_ref().map(|s| s.stream_id)
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2ConnectionBlobMeta, Vec<u8>)> {
        encode_secure_http2_connection(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttp2ConnectionBlobMeta, Vec<u8>)> {
        encode_secure_http2_connection_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(stream: TcpStream, data: &[u8]) -> io::Result<(SecureHttp2ConnectionBlobMeta, Self)> {
        decode_secure_http2_connection(stream, data)
    }
}

fn check_alpn(negotiated_protocol: Option<AlpnProtocol>) -> Result<()> {
    match negotiated_protocol {
        Some(protocol) if protocol != AlpnProtocol::Http2 => Err(Http2Error::Protocol(
            ErrorCode::ProtocolError,
            format!("HTTP/2 connection requires h2 protocol, got: {}", protocol.name()),
        )),
        _ => Ok(()),
    }
}

fn strip_padding(frame: &Frame) -> Result<&[u8]> {
    let payload = frame.payload.as_slice();
    if !frame.header.flags.has(FrameFlags::PADDED) {
        return Ok(payload);
    }

    let (&pad_length, rest) = payload.split_first().ok_or_else(|| {
        Http2Error::Protocol(ErrorCode::FrameSizeError, "padded frame is missing its pad length".to_string())
    })?;

    rest.len().checked_sub(pad_length as usize).map(|len| &rest[..len]).ok_or_else(|| {
        Http2Error::Protocol(ErrorCode::ProtocolError, "padding exceeds the frame payload".to_string())
    })
}

fn validate_header_block(headers: &[(String, String)], extended_connect_enabled: bool) -> std::result::Result<HeaderBlockKind, String> {
    let mut pseudo: HashMap<&str, &str> = HashMap::new();
    for (name, value) in headers {
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(format!("invalid header name '{}'", name));
        }

        if name.starts_with(':') {
            if !REQUEST_PSEUDO_HEADERS.contains(&name.as_str()) && name != ":status" {
                return Err(format!("unknown pseudo-header '{}'", name));
            }

            pseudo.insert(name, value);
        } else if CONNECTION_SPECIFIC_HEADERS.contains(&name.as_str()) || (name == "te" && value != "trailers") {
            return Err(format!("connection-specific header '{}'", name));
        }
    }

    if pseudo.is_empty() {
        return Ok(HeaderBlockKind::Trailers);
    }

    if pseudo.contains_key(":status") {
        if pseudo.len() != 1 {
            return Err("response mixes in request pseudo-headers".to_string());
        }

        return Ok(HeaderBlockKind::Response);
    }

    let method = *pseudo.get(":method").ok_or("request is missing :method")?;
    if method == "CONNECT" {
        if pseudo.contains_key(":protocol") {
            if !extended_connect_enabled {
                return Err("extended CONNECT was not enabled".to_string());
            }

            if [":scheme", ":path", ":authority"].iter().any(|name| !pseudo.contains_key(name)) {
                return Err("extended CONNECT requires :scheme, :path and :authority".to_string());
            }
        } else {
            if pseudo.contains_key(":scheme") || pseudo.contains_key(":path") {
                return Err("CONNECT must not include :scheme or :path".to_string());
            }

            if !pseudo.contains_key(":authority") {
                return Err("CONNECT requires :authority".to_string());
            }
        }
    } else {
        if pseudo.contains_key(":protocol") {
            return Err("the :protocol pseudo-header requires CONNECT".to_string());
        }

        if !pseudo.contains_key(":scheme") || !pseudo.contains_key(":path") {
            return Err("request is missing :scheme or :path".to_string());
        }
    }

    Ok(HeaderBlockKind::Request)
}

pub fn select_secure_http2_connection_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http2_connection(connection: &Http2Connection, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2ConnectionBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http2_connection(connection)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate connection blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http2_connection_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let nonce_b64 = pem::encode(&nonce);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = HTTP2_CONNECTION_BLOB_MAGIC,
        encoding = selected_algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
        issued_at = issued_at_unix
    );

    let mut blob = header.into_bytes();
    blob.extend_from_slice(&encoded_payload);

    Ok((
        SecureHttp2ConnectionBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64,
            digest_b64,
            tag_b64,
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix,
        },
        blob,
    ))
}

pub fn encode_secure_http2_connection_auto(connection: &Http2Connection, accept_encoding: &str) -> io::Result<(SecureHttp2ConnectionBlobMeta, Vec<u8>)> {
    let selected = select_secure_http2_connection_algorithm(accept_encoding);
    encode_secure_http2_connection(connection, selected)
}

pub fn decode_secure_http2_connection(stream: TcpStream, data: &[u8]) -> io::Result<(SecureHttp2ConnectionBlobMeta, Http2Connection)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http2_connection_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_http2_connection_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connection blob HMAC mismatch",
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
                "raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connection blob digest mismatch",
        ));
    }

    let connection = deserialize_http2_connection(stream, &raw_payload)?;
    Ok((meta, connection))
}

fn serialize_http2_connection(connection: &Http2Connection) -> io::Result<Vec<u8>> {
    let mut lines = Vec::new();

    lines.push(format!("role={}", connection.role.as_str()));
    lines.push(format!("next-stream-id={}", connection.next_stream_id));
    lines.push(format!("last-stream-id={}", connection.last_stream_id));
    lines.push(format!("goaway-sent={}", connection.goaway_sent));
    lines.push(format!("goaway-received={}", connection.goaway_received));
    lines.push(format!("goaway-final-sent={}", connection.goaway_final_sent));
    if let Some(last) = connection.local_goaway_last_stream_id {
        lines.push(format!("local-goaway-last-stream-id={}", last));
    }

    lines.push(format!("highest-peer-stream-id={}", connection.highest_peer_stream_id));
    let mut peer_streams: Vec<u32> = connection.peer_initiated_streams.iter().copied().collect();
    peer_streams.sort_unstable();
    lines.push(format!(
        "peer-initiated-streams={}",
        peer_streams.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",")
    ));

    lines.push(format!("local-settings-sent={}", connection.local_settings_sent));
    lines.push(format!("peer-settings-received={}", connection.peer_settings_received));
    lines.push(format!("max-frame-size={}", connection.max_frame_size));
    lines.push(format!("negotiated-protocol-present={}", connection.negotiated_protocol.is_some()));
    if let Some(protocol) = connection.negotiated_protocol {
        lines.push(format!(
            "negotiated-protocol-wire={}",
            pem::encode(protocol.wire_format())
        ));
    }

    let (_, local_settings_blob) = encode_secure_settings(&connection.local_settings,  CompressionAlgorithm::Identity)?;
    let (_, remote_settings_blob) = encode_secure_settings(&connection.remote_settings,  CompressionAlgorithm::Identity)?;
    let (_, flow_control_blob) = encode_secure_flow_control(&connection.connection_flow_control, CompressionAlgorithm::Identity)?;
    let (_, priority_tree_blob) = encode_secure_priority_tree(&connection.priority_tree, CompressionAlgorithm::Identity)?;
    let (_, scheduler_blob) = encode_secure_priority_scheduler(&connection.scheduler, CompressionAlgorithm::Identity)?;
    let (_, push_manager_blob) = encode_secure_push_manager(&connection.push_manager, CompressionAlgorithm::Identity)?;
    let (_, encoder_blob) = encode_secure_hpack_codec(&connection.encoder, CompressionAlgorithm::Identity)?;
    let (_, decoder_blob) = encode_secure_hpack_codec(&connection.decoder, CompressionAlgorithm::Identity)?;
    lines.push(format!("hpack-encoder-blob={}", pem::encode(&encoder_blob)));
    lines.push(format!("hpack-decoder-blob={}", pem::encode(&decoder_blob)));
    lines.push(format!(
        "local-settings-blob={}",
        pem::encode(&local_settings_blob)
    ));

    lines.push(format!(
        "remote-settings-blob={}",
        pem::encode(&remote_settings_blob)
    ));

    lines.push(format!(
        "connection-flow-control-blob={}",
        pem::encode(&flow_control_blob)
    ));

    lines.push(format!(
        "priority-tree-blob={}",
        pem::encode(&priority_tree_blob)
    ));

    lines.push(format!("scheduler-blob={}", pem::encode(&scheduler_blob)));
    lines.push(format!(
        "push-manager-blob={}",
        pem::encode(&push_manager_blob)
    ));

    let mut stream_ids: Vec<u32> = connection.streams.keys().copied().collect();
    stream_ids.sort_unstable();
    lines.push(format!("stream-count={}", stream_ids.len()));
    for (idx, stream_id) in stream_ids.iter().enumerate() {
        let stream = connection.streams.get(stream_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing stream in connection map",
            )
        })?;

        let (_, stream_blob) = encode_secure_http2_stream(stream, CompressionAlgorithm::Identity)?;
        lines.push(format!("stream-{}-id={}", idx, stream_id));
        lines.push(format!("stream-{}-blob={}", idx, pem::encode(&stream_blob)));
    }

    lines.push(format!(
        "continuation-present={}",
        connection.continuation_state.is_some()
    ));

    if let Some(state) = &connection.continuation_state {
        lines.push(format!("continuation-stream-id={}", state.stream_id));
        lines.push(format!(
            "continuation-header-block={}",
            pem::encode(&state.header_block_fragments)
        ));

        lines.push(format!("continuation-end-stream={}", state.end_stream));
        lines.push(format!(
            "continuation-is-push-promise={}",
            state.is_push_promise
        ));

        lines.push(format!(
            "continuation-parent-present={}",
            state.parent_stream_id.is_some()
        ));

        if let Some(parent_id) = state.parent_stream_id {
            lines.push(format!("continuation-parent-id={}", parent_id));
        }

        if let Some(promised_id) = state.promised_stream_id {
            lines.push(format!("continuation-promised-id={}", promised_id));
        }

        if let Some(priority) = &state.priority {
            lines.push(format!("continuation-priority={}", pem::encode(&priority.serialize())));
        }

        lines.push(format!("continuation-frame-count={}", state.frame_count));
    }

    Ok(lines.join("\n").into_bytes())
}

fn deserialize_http2_connection(stream: TcpStream, raw_payload: &[u8]) -> io::Result<Http2Connection> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "connection payload is not valid UTF-8",
        )
    })?;

    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid connection payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let role = match kv.get("role") {
        Some(value) => Role::from_str(value).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid role")
        })?,
        None => Role::Client,
    };

    let next_stream_id = parse_u32(required_field(&kv, "next-stream-id")?, "next-stream-id")?;
    let last_stream_id = parse_u32(required_field(&kv, "last-stream-id")?, "last-stream-id")?;
    let goaway_sent = parse_bool(required_field(&kv, "goaway-sent")?, "goaway-sent")?;
    let goaway_received = parse_bool(
        required_field(&kv, "goaway-received")?,
        "goaway-received",
    )?;

    let max_frame_size = parse_u32(required_field(&kv, "max-frame-size")?, "max-frame-size")?;
    let negotiated_protocol_present = kv.get("negotiated-protocol-present").map(|v| parse_bool(v, "negotiated-protocol-present")).transpose()?.unwrap_or(false);
    let negotiated_protocol = if negotiated_protocol_present {
        let wire = decode_blob_field(
            required_field(&kv, "negotiated-protocol-wire")?,
            "negotiated-protocol-wire",
        )?;

        Some(AlpnProtocol::from_wire(&wire).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid negotiated-protocol-wire value",
            )
        })?)
    } else {
        None
    };
    
    let local_settings_blob = decode_blob_field(
        required_field(&kv, "local-settings-blob")?,
        "local-settings-blob",
    )?;

    let remote_settings_blob = decode_blob_field(
        required_field(&kv, "remote-settings-blob")?,
        "remote-settings-blob",
    )?;

    let flow_control_blob = decode_blob_field(
        required_field(&kv, "connection-flow-control-blob")?,
        "connection-flow-control-blob",
    )?;

    let priority_tree_blob = decode_blob_field(
        required_field(&kv, "priority-tree-blob")?,
        "priority-tree-blob",
    )?;

    let scheduler_blob =
        decode_blob_field(required_field(&kv, "scheduler-blob")?, "scheduler-blob")?;

    let push_manager_blob = decode_blob_field(
        required_field(&kv, "push-manager-blob")?,
        "push-manager-blob",
    )?;

    let (_, local_settings) = decode_secure_settings(&local_settings_blob)?;
    let (_, remote_settings) = decode_secure_settings(&remote_settings_blob)?;
    let (_, connection_flow_control) = decode_secure_flow_control(&flow_control_blob)?;
    let (_, priority_tree) = decode_secure_priority_tree(&priority_tree_blob)?;
    let (_, scheduler) = decode_secure_priority_scheduler(&scheduler_blob)?;
    let (_, push_manager) = decode_secure_push_manager(&push_manager_blob)?;

    let stream_count = parse_usize(required_field(&kv, "stream-count")?, "stream-count")?;
    let mut streams = HashMap::new();
    for idx in 0..stream_count {
        let stream_id = parse_u32(
            required_field(&kv, &format!("stream-{}-id", idx))?,
            &format!("stream-{}-id", idx),
        )?;

        let stream_blob = decode_blob_field(
            required_field(&kv, &format!("stream-{}-blob", idx))?,
            &format!("stream-{}-blob", idx),
        )?;

        let (_, decoded_stream) = decode_secure_http2_stream(&stream_blob)?;
        streams.insert(stream_id, decoded_stream);
    }

    let continuation_present = parse_bool(
        required_field(&kv, "continuation-present")?,
        "continuation-present",
    )?;

    let continuation_state = if continuation_present {
        let stream_id = parse_u32(
            required_field(&kv, "continuation-stream-id")?,
            "continuation-stream-id",
        )?;

        let header_block = decode_blob_field(
            required_field(&kv, "continuation-header-block")?,
            "continuation-header-block",
        )?;

        let end_stream = parse_bool(
            required_field(&kv, "continuation-end-stream")?,
            "continuation-end-stream",
        )?;

        let is_push_promise = parse_bool(
            required_field(&kv, "continuation-is-push-promise")?,
            "continuation-is-push-promise",
        )?;

        let parent_present = parse_bool(
            required_field(&kv, "continuation-parent-present")?,
            "continuation-parent-present",
        )?;

        let parent_stream_id = if parent_present {
            Some(parse_u32(
                required_field(&kv, "continuation-parent-id")?,
                "continuation-parent-id",
            )?)
        } else {
            None
        };

        let promised_stream_id = optional_u32(&kv, "continuation-promised-id")?;
        let priority = kv.get("continuation-priority").map(|v| {
            decode_blob_field(v, "continuation-priority").map(|bytes| Priority::parse(&bytes))
        }).transpose()?;

        let frame_count = kv.get("continuation-frame-count").map(|v| {
            parse_usize(v, "continuation-frame-count")
        }).transpose()?.unwrap_or(1);

        Some(ContinuationState {
            stream_id,
            header_block_fragments: header_block,
            end_stream,
            is_push_promise,
            parent_stream_id,
            priority,
            promised_stream_id,
            frame_count,
        })
    } else {
        None
    };

    let decode_codec = |key: &str| -> io::Result<HpackCodec> {
        match kv.get(key) {
            Some(value) => Ok(decode_secure_hpack_codec(&decode_blob_field(value, key)?)?.1),
            None => Ok(HpackCodec::new(local_settings.header_table_size() as usize)),
        }
    };

    let encoder = decode_codec("hpack-encoder-blob")?;
    let decoder = decode_codec("hpack-decoder-blob")?;
    
    let optional_bool = |key: &str| kv.get(key).map(|v| parse_bool(v, key)).transpose();
    let goaway_final_sent = optional_bool("goaway-final-sent")?.unwrap_or(false);
    let local_settings_sent = optional_bool("local-settings-sent")?.unwrap_or(true);
    let peer_settings_received = optional_bool("peer-settings-received")?.unwrap_or(true);
    let local_goaway_last_stream_id = optional_u32(&kv, "local-goaway-last-stream-id")?;
    let highest_peer_stream_id = optional_u32(&kv, "highest-peer-stream-id")?.unwrap_or(0);
    let peer_initiated_streams = match kv.get("peer-initiated-streams") {
        Some(csv) => csv.split(',').filter(|id| !id.is_empty()).map(|id| {
            parse_u32(id, "peer-initiated-streams")
        }).collect::<io::Result<HashSet<u32>>>()?,
        None => HashSet::new(),
    };

    Ok(Http2Connection {
        stream: Box::new(stream),
        role,
        streams,
        next_stream_id,
        local_settings,
        remote_settings,
        connection_flow_control,
        encoder,
        decoder,
        priority_tree,
        last_stream_id,
        highest_peer_stream_id,
        peer_initiated_streams,
        goaway_sent,
        goaway_received,
        goaway_final_sent,
        local_goaway_last_stream_id,
        peer_goaway_error: None,
        goaway_unprocessed_streams: Vec::new(),
        shutdown_ping: None,
        continuation_state,
        scheduler,
        max_frame_size,
        push_manager,
        negotiated_protocol,
        local_settings_sent,
        peer_settings_received,
        pending_settings_acks: VecDeque::new(),
        pings_outstanding: HashMap::new(),
        last_ping_rtt: None,
        ack_timeout: DEFAULT_ACK_TIMEOUT,
        keepalive_interval: None,
        last_frame_received_at: Instant::now(),
        recent_resets: VecDeque::new(),
        max_resets_per_window: DEFAULT_MAX_RESETS_PER_WINDOW,
        reset_window: DEFAULT_RESET_WINDOW,
    })
}

fn optional_u32(kv: &HashMap<String, String>, key: &str) -> io::Result<Option<u32>> {
    kv.get(key).map(|v| parse_u32(v, key)).transpose()
}

fn decode_blob_field(value: &str, field: &str) -> io::Result<Vec<u8>> {
    pem::decode(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in connection payload", key),
        )
    })
}

fn parse_u32(v: &str, field: &str) -> io::Result<u32> {
    v.parse::<u32>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_bool(v: &str, field: &str) -> io::Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {}", field),
        )),
    }
}

fn compute_http2_connection_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP2_CONNECTION_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP2_CONNECTION_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing blob header/body separator",
    ))
}

fn parse_secure_http2_connection_meta(header: &str, body_len: usize) -> io::Result<SecureHttp2ConnectionBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP2_CONNECTION_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure connection blob magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure connection header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm =
                    CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    })?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure connection blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure connection blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure connection blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure connection blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure connection blob",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded-size mismatch: metadata {}, actual {}",
                encoded_size, body_len
            ),
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in secure connection blob",
        )
    })?;

    Ok(SecureHttp2ConnectionBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Http2Stream {
    pub fn get_send_data(&mut self, max_len: usize) -> Vec<u8> {
        let mut data = Vec::new();
        let mut remaining = max_len;
        while remaining > 0 && self.send_buffer_len() > 0 {
            if let Some(chunk) = self.send_buffer.pop_front() {
                let take = chunk.len().min(remaining);
                data.extend_from_slice(&chunk[..take]);
                remaining -= take;
                if take < chunk.len() {
                    self.send_buffer.push_front(chunk[take..].to_vec());
                    break;
                }
            }
        }
        
        data
    }

    pub fn queue_send_data(&mut self, data: Vec<u8>) -> Result<()> {
        self.send_buffer.push_back(data);
        Ok(())
    }

    pub fn send_buffer_len(&self) -> usize {
        self.send_buffer.iter().map(|chunk| chunk.len()).sum()
    }

    pub fn mark_send_complete(&mut self) {
        self.end_stream_sent = true;
    }

    pub fn is_send_complete(&self) -> bool {
        self.end_stream_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener as StdListener, TcpStream as StdStream};

    #[test]
    fn test_continuation_state() {
        let state = ContinuationState::new(1, true, false);
        assert_eq!(state.stream_id, 1);
        assert!(state.end_stream);
        assert!(!state.is_push_promise);
        assert!(state.header_block_fragments.is_empty());
    }
    
    struct Harness {
        conn: Http2Connection,
        peer: StdStream,
        peer_encoder: HpackCodec,
        peer_decoder: HpackCodec,
    }
    
    impl Harness {
        fn new() -> Self {
            Self::with_role(Role::Server)
        }
        
        fn client() -> Self {
            Self::with_role(Role::Client)
        }
        
        fn with_role(role: Role) -> Self {
            let listener = StdListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            Self {
                conn: Http2Connection::with_transport(stream, role).unwrap(),
                peer,
                peer_encoder: HpackCodec::new(4096),
                peer_decoder: HpackCodec::new(4096),
            }
        }
        
        fn feed(&mut self, frame: Frame) -> Result<()> {
            self.conn.dispatch_frame(frame)
        }
        
        fn block(&mut self, headers: &[(&str, &str)]) -> Vec<u8> {
            let headers: Vec<(String, String)> = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
            self.peer_encoder.encode_list(&headers)
        }
        
        fn open_request(&mut self, stream_id: u32, end_stream: bool) -> Result<()> {
            let block = self.block(&request_headers());
            self.feed(Frame::headers(stream_id, block, true, end_stream))
        }
        
        fn next_frame(&mut self) -> Frame {
            loop {
                let frame = Frame::read(&mut self.peer).unwrap();
                let is_settings_ack = frame.header.frame_type == FrameType::Settings && frame.header.flags.has(FrameFlags::ACK);
                if frame.header.frame_type != FrameType::WindowUpdate && !is_settings_ack {
                    return frame;
                }
            }
        }
        
        fn assert_alive(&mut self) {
            self.feed(Frame::ping(*b"liveness", false)).unwrap();
            let frame = self.next_frame();
            assert_eq!(frame.header.frame_type, FrameType::Ping, "unexpected {:?}", frame.header.frame_type);
            assert_eq!(frame.payload, b"liveness");
        }
        
        fn expect_rst(&mut self, stream_id: u32, code: ErrorCode) {
            let frame = self.next_frame();
            assert_eq!(frame.header.frame_type, FrameType::RstStream);
            assert_eq!(frame.header.stream_id, stream_id);
            assert_eq!(frame.payload, (code as u32).to_be_bytes());
        }
        
        fn expect_goaway(&mut self, last_stream_id: u32, code: ErrorCode) {
            let frame = self.next_frame();
            assert_eq!(frame.header.frame_type, FrameType::GoAway);
            assert_eq!(&frame.payload[..4], &last_stream_id.to_be_bytes());
            assert_eq!(&frame.payload[4..8], &(code as u32).to_be_bytes());
        }
        
        fn peer_settings(&mut self, entries: &[(SettingId, u32)]) -> Result<()> {
            self.feed(Frame::settings(entries.iter().map(|(id, v)| (*id as u16, *v)).collect()))
        }
    }
    
    fn request_headers() -> Vec<(&'static str, &'static str)> {
        vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "example.com")]
    }
    
    fn padded(mut frame: Frame, pad: u8) -> Frame {
        let mut payload = vec![pad];
        payload.extend_from_slice(&frame.payload);
        payload.extend(std::iter::repeat(0).take(pad as usize));
        frame.header.flags.set(FrameFlags::PADDED);
        frame.header.length = payload.len() as u32;
        frame.payload = payload;

        frame
    }
    
    fn with_flags(mut frame: Frame, flags: u8) -> Frame {
        frame.header.flags.set(flags);

        frame
    }
    
    fn protocol_code(result: Result<()>) -> ErrorCode {
        match result {
            Err(Http2Error::Protocol(code, _)) => code,
            other => panic!("expected a connection error, got {:?}", other),
        }
    }
    
    fn settings_entries(frame: &Frame) -> Vec<(u16, u32)> {
        frame.payload.chunks_exact(6).map(|entry| {
            (u16::from_be_bytes([entry[0], entry[1]]), u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))
        }).collect()
    }
    
    #[test]
    fn test_server_handshake_reads_client_preface() {
        let mut h = Harness::new();
        h.peer.write_all(CLIENT_PREFACE).unwrap();
        Frame::settings(vec![(SettingId::MaxConcurrentStreams as u16, 50)]).write(&mut h.peer).unwrap();
        h.conn.handshake().unwrap();
        
        let settings = Frame::read(&mut h.peer).unwrap();
        assert_eq!(settings.header.frame_type, FrameType::Settings);
        assert!(!settings.header.flags.has(FrameFlags::ACK));
        assert!(settings_entries(&settings).contains(&(SettingId::EnablePush as u16, 0)));
        
        let ack = Frame::read(&mut h.peer).unwrap();
        assert!(ack.header.flags.has(FrameFlags::ACK));
        assert_eq!(h.conn.peer_max_concurrent_streams(), 50);
    }
    
    #[test]
    fn test_server_rejects_invalid_client_preface() {
        let mut h = Harness::new();
        h.peer.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(protocol_code(h.conn.handshake()), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_server_requires_settings_after_preface() {
        let mut h = Harness::new();
        h.peer.write_all(CLIENT_PREFACE).unwrap();
        Frame::ping(*b"too-soon", false).write(&mut h.peer).unwrap();
        assert_eq!(protocol_code(h.conn.handshake()), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_client_handshake_sends_preface() {
        let mut h = Harness::client();
        Frame::settings(vec![(SettingId::EnableConnectProtocol as u16, 1)]).write(&mut h.peer).unwrap();
        h.conn.handshake().unwrap();

        let mut preface = [0u8; CLIENT_PREFACE.len()];
        h.peer.read_exact(&mut preface).unwrap();
        assert_eq!(&preface[..], CLIENT_PREFACE);
        let settings = Frame::read(&mut h.peer).unwrap();
        assert_eq!(settings.header.frame_type, FrameType::Settings);
        assert!(settings_entries(&settings).contains(&(SettingId::EnablePush as u16, 1)));
        assert!(Frame::read(&mut h.peer).unwrap().header.flags.has(FrameFlags::ACK));
        assert!(h.conn.peer_supports_extended_connect());
    }
    
    #[test]
    fn test_roles_open_streams_with_their_own_parity() {
        let mut client = Harness::client();
        assert_eq!(client.conn.create_stream().unwrap(), 1);
        assert_eq!(client.conn.create_stream().unwrap(), 3);

        let mut server = Harness::new();
        assert_eq!(server.conn.role(), Role::Server);
        assert_eq!(server.conn.create_stream().unwrap(), 2);
    }
    
    #[test]
    fn test_client_rejects_priority_update() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream().unwrap();
        let result = h.feed(Frame::priority_update(stream_id, ExtensiblePriority::new(0, false)));
        assert_eq!(protocol_code(result), ErrorCode::ProtocolError);
        h.expect_goaway(0, ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_client_rejects_server_enabling_push() {
        let mut h = Harness::client();
        h.peer_settings(&[(SettingId::EnablePush, 0)]).unwrap();
        assert_eq!(protocol_code(h.peer_settings(&[(SettingId::EnablePush, 1)])), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_client_rejects_server_opening_streams_with_headers() {
        let mut h = Harness::client();
        let block = h.block(&[(":status", "200")]);
        assert_eq!(protocol_code(h.feed(Frame::headers(2, block, true, false))), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_server_rejects_push_promise() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        let block = h.block(&request_headers());
        assert_eq!(protocol_code(h.feed(Frame::push_promise(1, 2, block, true))), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_server_rejects_client_using_even_stream_ids() {
        let mut h = Harness::new();
        let block = h.block(&request_headers());
        assert_eq!(protocol_code(h.feed(Frame::headers(2, block, true, true))), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_server_cannot_enable_push() {
        let mut h = Harness::new();
        assert!(!h.conn.local_settings().enable_push());
        assert!(h.conn.initial_settings().contains(&(SettingId::EnablePush as u16, 0)));
        assert!(matches!(h.conn.set_local_setting(SettingId::EnablePush, 1), Err(Http2Error::NotPermitted(_))));
    }
    
    #[test]
    fn test_server_answers_request_over_any_transport() {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let mut client = StdStream::connect(listener.local_addr().unwrap()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let mut conn = Http2Connection::new_server_with_alpn(server_side, Some(AlpnProtocol::Http2)).unwrap();

        let mut client_encoder = HpackCodec::new(4096);
        let mut client_decoder = HpackCodec::new(4096);
        client.write_all(CLIENT_PREFACE).unwrap();
        Frame::settings(Vec::new()).write(&mut client).unwrap();
        let request: Vec<(String, String)> = request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        Frame::headers(1, client_encoder.encode_list(&request), true, true).write(&mut client).unwrap();

        conn.handshake().unwrap();
        conn.receive_frame().unwrap();
        let stream = conn.get_stream(1).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
        assert!(stream.response_headers().iter().any(|(n, v)| n == ":path" && v == "/"));

        let response = vec![(":status".to_string(), "200".to_string())];
        conn.send_request(1, response, Some(b"hello".to_vec())).unwrap();
        assert!(conn.get_stream(1).unwrap().is_closed());
        conn.close_stream(1).unwrap();
        assert!(conn.get_stream(1).is_none());

        let frames: Vec<Frame> = (0..4).map(|_| Frame::read(&mut client).unwrap()).collect();
        assert_eq!(frames[0].header.frame_type, FrameType::Settings);
        assert!(frames[1].header.flags.has(FrameFlags::ACK));
        assert_eq!(frames[2].header.frame_type, FrameType::Headers);
        assert_eq!(client_decoder.decode(&frames[2].payload).unwrap().get(":status"), Some(&"200".to_string()));
        assert_eq!(frames[3].header.frame_type, FrameType::Data);
        assert_eq!(frames[3].payload, b"hello");
        assert!(frames[3].header.flags.has(FrameFlags::END_STREAM));
    }
    
    #[test]
    fn test_padded_headers_split_across_continuations() {
        let mut h = Harness::new();
        let block = h.block(&request_headers());
        let (first, rest) = block.split_at(3);
        let (middle, last) = rest.split_at(2);

        h.feed(padded(Frame::headers(1, first.to_vec(), false, true), 4)).unwrap();
        assert_eq!(h.conn.pending_continuation_stream(), Some(1));
        h.feed(with_flags(Frame::continuation(1, middle.to_vec(), false), 0x80)).unwrap();
        h.feed(Frame::continuation(1, Vec::new(), false)).unwrap();
        h.feed(Frame::continuation(1, last.to_vec(), true)).unwrap();

        assert!(!h.conn.has_pending_continuation());
        let stream = h.conn.get_stream(1).unwrap();
        assert!(stream.response_headers().iter().any(|(n, v)| n == ":path" && v == "/"));
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }
    
    #[test]
    fn test_priority_fields_are_consumed_when_rfc7540_priorities_disabled() {
        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::NoRfc7540Priorities, 1).unwrap();
        let mut payload = Priority::new(0, 200, false).serialize().to_vec();
        payload.extend(h.block(&request_headers()));
        h.feed(with_flags(Frame::headers(1, payload, true, true), FrameFlags::PRIORITY)).unwrap();

        assert!(h.conn.get_stream(1).unwrap().headers_received);
        assert_eq!(h.conn.get_stream_priority(1).unwrap().weight, Priority::default().weight);
    }
    
    #[test]
    fn test_headers_priority_applies_and_rejects_self_dependency() {
        let mut h = Harness::new();
        let mut payload = Priority::new(0, 200, false).serialize().to_vec();
        payload.extend(h.block(&request_headers()));
        h.feed(with_flags(Frame::headers(1, payload, true, false), FrameFlags::PRIORITY)).unwrap();
        assert_eq!(h.conn.get_stream_priority(1).unwrap().weight, 200);

        let mut payload = Priority::new(3, 16, false).serialize().to_vec();
        payload.extend(h.block(&request_headers()));
        h.feed(with_flags(Frame::headers(3, payload, true, false), FrameFlags::PRIORITY)).unwrap();
        h.expect_rst(3, ErrorCode::ProtocolError);
        h.assert_alive();
    }
    
    #[test]
    fn test_interleaved_frame_during_continuation_is_connection_error() {
        let mut h = Harness::new();
        let block = h.block(&request_headers());
        h.feed(Frame::headers(1, block, false, false)).unwrap();
        let unknown = Frame::new(FrameType::Unknown, 0, 0, vec![1, 2, 3]);
        assert_eq!(protocol_code(h.feed(unknown)), ErrorCode::ProtocolError);
        h.expect_goaway(0, ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_continuation_on_wrong_stream_or_without_headers_is_rejected() {
        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::continuation(1, vec![], true))), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        let block = h.block(&request_headers());
        h.feed(Frame::headers(1, block, false, false)).unwrap();
        assert_eq!(protocol_code(h.feed(Frame::continuation(3, vec![], true))), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_continuation_flood_is_bounded() {
        let mut h = Harness::new();
        h.feed(Frame::headers(1, vec![0x82], false, false)).unwrap();
        for _ in 1..MAX_CONTINUATION_FRAMES {
            h.feed(Frame::continuation(1, Vec::new(), false)).unwrap();
        }
        let result = h.feed(Frame::continuation(1, Vec::new(), false));
        assert_eq!(protocol_code(result), ErrorCode::EnhanceYourCalm);
    }
    
    #[test]
    fn test_oversized_header_block_is_rejected() {
        let mut h = Harness::new();
        h.feed(Frame::headers(1, vec![0; 16 * 1024], false, false)).unwrap();
        let mut result = Ok(());
        for _ in 0..(MAX_HEADER_BLOCK_SIZE / (16 * 1024)) {
            result = h.feed(Frame::continuation(1, vec![0; 16 * 1024], false));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(protocol_code(result), ErrorCode::EnhanceYourCalm);
    }
    
    #[test]
    fn test_invalid_padding_is_connection_error() {
        let mut h = Harness::new();
        let mut frame = Frame::headers(1, vec![5, 0x82], true, false);
        frame.header.flags.set(FrameFlags::PADDED);
        assert_eq!(protocol_code(h.feed(frame)), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_unknown_frames_are_ignored() {
        let mut h = Harness::new();
        h.feed(Frame::new(FrameType::Unknown, 0xff, 0, vec![9; 32])).unwrap();
        h.assert_alive();
    }
    
    #[test]
    fn test_trailers_end_the_stream() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.feed(Frame::data(1, b"body".to_vec(), false)).unwrap();
        let trailers = h.block(&[("x-checksum", "abc")]);
        h.feed(Frame::headers(1, trailers, true, true)).unwrap();

        let stream = h.conn.get_stream(1).unwrap();
        assert_eq!(stream.trailers(), &[("x-checksum".to_string(), "abc".to_string())]);
        assert_eq!(stream.data(), b"body");
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }
    
    #[test]
    fn test_trailers_without_end_stream_reset_only_that_stream() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        let trailers = h.block(&[("x-checksum", "abc")]);
        h.feed(Frame::headers(1, trailers, true, false)).unwrap();
        h.expect_rst(1, ErrorCode::ProtocolError);
        h.assert_alive();
    }
    
    #[test]
    fn test_malformed_requests_are_stream_errors() {
        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![(":method", "GET"), (":path", "/")],
            vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("connection", "close")],
            vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("te", "gzip")],
            vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":bogus", "x")],
            vec![(":method", "GET"), (":status", "200")],
            vec![(":method", "CONNECT"), (":authority", "a:443"), (":path", "/")],
        ];

        for (i, headers) in cases.iter().enumerate() {
            let mut h = Harness::new();
            let stream_id = 2 * i as u32 + 1;
            let block = h.block(headers);
            h.feed(Frame::headers(stream_id, block, true, true)).unwrap();
            h.expect_rst(stream_id, ErrorCode::ProtocolError);
            assert!(h.conn.get_stream(stream_id).is_none());
        }

        let mut h = Harness::new();
        let mut block = vec![0x82, 0x87, 0x84, 0x00, 0x07];
        block.extend_from_slice(b"X-Upper");
        block.extend_from_slice(&[0x01, b'x']);
        h.feed(Frame::headers(1, block, true, true)).unwrap();
        h.expect_rst(1, ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_hpack_state_survives_refused_streams() {
        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::MaxConcurrentStreams, 0).unwrap();
        let block = h.block(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("x-shared", "v")]);
        h.feed(Frame::headers(1, block, true, true)).unwrap();
        h.expect_rst(1, ErrorCode::RefusedStream);
        
        h.conn.set_local_setting(SettingId::MaxConcurrentStreams, 10).unwrap();
        let block = vec![0x82, 0x87, 0x84, 0x80 | 63, 0x80 | 62];
        h.feed(Frame::headers(3, block, true, true)).unwrap();
        assert!(h.conn.get_stream(3).unwrap().response_headers().iter().any(|(n, v)| n == "x-shared" && v == "v"));
    }
    
    #[test]
    fn test_stream_flow_control_overflow_resets_only_that_stream() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.open_request(3, false).unwrap();
        h.feed(Frame::window_update(1, 0x7fff_ffff)).unwrap();
        h.expect_rst(1, ErrorCode::FlowControlError);
        
        assert!(h.conn.get_stream(1).is_none());
        assert!(h.conn.get_stream(3).is_some());
        h.assert_alive();
    }
    
    #[test]
    fn test_zero_window_increment_is_stream_or_connection_error() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.feed(Frame::window_update(1, 0)).unwrap();
        h.expect_rst(1, ErrorCode::ProtocolError);
        h.assert_alive();

        assert_eq!(protocol_code(h.feed(Frame::window_update(0, 0))), ErrorCode::ProtocolError);
        h.expect_goaway(1, ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_data_on_closed_stream_is_stream_error_and_keeps_connection_window() {
        let mut h = Harness::new();
        h.open_request(1, true).unwrap();
        h.feed(padded(Frame::data(1, b"late".to_vec(), false), 3)).unwrap();

        let update = Frame::read(&mut h.peer).unwrap();
        assert_eq!(update.header.frame_type, FrameType::WindowUpdate);
        assert_eq!(update.header.stream_id, 0);
        assert_eq!(update.payload, 8u32.to_be_bytes());
        h.expect_rst(1, ErrorCode::StreamClosed);
        h.assert_alive();
    }
    
    #[test]
    fn test_padded_data_is_stripped() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.feed(padded(Frame::data(1, b"hello".to_vec(), true), 10)).unwrap();
        assert_eq!(h.conn.get_stream(1).unwrap().data(), b"hello");
    }
    
    #[test]
    fn test_frames_on_idle_streams_are_connection_errors() {
        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::data(5, b"x".to_vec(), false))), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::rst_stream(5, ErrorCode::Cancel as u32))), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::window_update(5, 1))), ErrorCode::ProtocolError);
    }
    
    #[test]
    fn test_hpack_failure_is_connection_error() {
        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::headers(1, vec![0xff, 0xff], true, false))), ErrorCode::CompressionError);
        h.expect_goaway(0, ErrorCode::CompressionError);
    }
    
    #[test]
    fn test_inbound_streams_above_local_limit_are_refused() {
        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::MaxConcurrentStreams, 2).unwrap();
        h.open_request(1, false).unwrap();
        h.open_request(3, false).unwrap();
        h.open_request(5, false).unwrap();
        h.expect_rst(5, ErrorCode::RefusedStream);
        assert!(h.conn.get_stream(5).is_none());
        
        h.feed(Frame::rst_stream(1, ErrorCode::Cancel as u32)).unwrap();
        h.open_request(7, false).unwrap();
        assert!(h.conn.get_stream(7).is_some());
    }

    #[test]
    fn test_local_default_limit_is_advertised() {
        let h = Harness::new();
        assert_eq!(h.conn.local_settings().max_concurrent_streams(), 100);
        assert!(h.conn.initial_settings().contains(&(SettingId::MaxConcurrentStreams as u16, 100)));
    }
    
    #[test]
    fn test_outbound_streams_respect_peer_limit() {
        let mut h = Harness::client();
        h.peer_settings(&[(SettingId::MaxConcurrentStreams, 1)]).unwrap();
        let first = h.conn.create_stream().unwrap();
        assert!(!h.conn.can_open_stream());
        assert!(matches!(h.conn.create_stream(), Err(Http2Error::StreamLimitReached(1))));
        
        h.peer_settings(&[(SettingId::InitialWindowSize, 1000)]).unwrap();
        assert_eq!(h.conn.peer_max_concurrent_streams(), 1);
        
        h.conn.close_stream(first).unwrap();
        assert!(h.conn.create_stream().is_ok());
    }

    #[test]
    fn test_rapid_reset_triggers_enhance_your_calm() {
        let mut h = Harness::new();
        h.conn.set_reset_rate_limit(5, Duration::from_secs(60));
        let mut result = Ok(());
        for i in 0..6u32 {
            let stream_id = 2 * i + 1;
            h.open_request(stream_id, false).unwrap();
            result = h.feed(Frame::rst_stream(stream_id, ErrorCode::Cancel as u32));
            assert!(h.conn.get_stream(stream_id).is_none());
        }

        assert_eq!(protocol_code(result), ErrorCode::EnhanceYourCalm);
        h.expect_goaway(11, ErrorCode::EnhanceYourCalm);
        assert!(h.conn.streams.is_empty());
    }

    #[test]
    fn test_peer_provoked_resets_count_toward_the_limit() {
        let mut h = Harness::new();
        h.conn.set_reset_rate_limit(2, Duration::from_secs(60));
        let mut last = Ok(());
        for i in 0..3u32 {
            let stream_id = 2 * i + 1;
            h.open_request(stream_id, false).unwrap();
            last = h.feed(Frame::window_update(stream_id, 0));
        }
        assert_eq!(protocol_code(last), ErrorCode::EnhanceYourCalm);
    }

    #[test]
    fn test_resets_outside_the_window_are_forgotten() {
        let mut h = Harness::new();
        h.conn.set_reset_rate_limit(1, Duration::from_millis(20));
        h.open_request(1, false).unwrap();
        h.feed(Frame::rst_stream(1, ErrorCode::Cancel as u32)).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        h.open_request(3, false).unwrap();
        h.feed(Frame::rst_stream(3, ErrorCode::Cancel as u32)).unwrap();
    }

    #[test]
    fn test_peer_cancelling_our_streams_is_not_abuse() {
        let mut h = Harness::client();
        h.conn.set_reset_rate_limit(1, Duration::from_secs(60));
        for _ in 0..5 {
            let stream_id = h.conn.create_stream().unwrap();
            h.feed(Frame::rst_stream(stream_id, ErrorCode::Cancel as u32)).unwrap();
            assert!(h.conn.get_stream(stream_id).unwrap().is_closed());
        }
    }

    #[test]
    fn test_scheduler_does_not_grow_with_reset_churn() {
        let mut h = Harness::new();
        h.conn.set_reset_rate_limit(usize::MAX, Duration::from_secs(60));
        for i in 0..500u32 {
            let stream_id = 2 * i + 1;
            h.open_request(stream_id, false).unwrap();
            h.feed(Frame::rst_stream(stream_id, ErrorCode::Cancel as u32)).unwrap();
        }
        assert!(h.conn.get_scheduler_stats().total_streams <= super::super::scheduler::DEFAULT_MAX_CLOSED_RETAINED);
        assert!(h.conn.streams.is_empty());
    }

    #[test]
    fn test_close_reports_highest_peer_stream() {
        let mut h = Harness::new();
        h.open_request(1, true).unwrap();
        h.open_request(3, true).unwrap();
        h.conn.close().unwrap();
        h.expect_goaway(3, ErrorCode::NoError);

        h.conn.close().unwrap();
        h.assert_alive();
    }

    #[test]
    fn test_graceful_shutdown_is_two_phase() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.conn.begin_graceful_shutdown().unwrap();
        h.expect_goaway(MAX_STREAM_ID, ErrorCode::NoError);
        let ping = h.next_frame();
        assert_eq!(ping.header.frame_type, FrameType::Ping);
        assert!(!h.conn.graceful_shutdown_ready());

        h.open_request(3, false).unwrap();
        assert!(h.conn.get_stream(3).is_some());
        assert!(matches!(h.conn.create_stream(), Err(Http2Error::ConnectionClosed)));

        let mut token = [0u8; 8];
        token.copy_from_slice(&ping.payload);
        h.feed(Frame::ping(token, true)).unwrap();
        assert!(h.conn.graceful_shutdown_ready());

        h.conn.close().unwrap();
        h.expect_goaway(3, ErrorCode::NoError);

        h.open_request(5, false).unwrap();
        assert!(h.conn.get_stream(5).is_none());
        h.feed(Frame::data(5, b"x".to_vec(), false)).unwrap();
        h.assert_alive();
    }

    #[test]
    fn test_peer_goaway_marks_unprocessed_streams() {
        let mut h = Harness::client();
        let ids: Vec<u32> = (0..3).map(|_| h.conn.create_stream().unwrap()).collect();
        h.feed(Frame::goaway(ids[0], ErrorCode::NoError as u32, Vec::new())).unwrap();

        assert_eq!(h.conn.goaway_unprocessed_streams(), &ids[1..]);
        assert!(!h.conn.get_stream(ids[0]).unwrap().is_closed());
        assert!(h.conn.get_stream(ids[2]).unwrap().is_closed());
        assert_eq!(h.conn.peer_goaway_error(), Some(ErrorCode::NoError));

        h.feed(Frame::goaway(ids[2], ErrorCode::InternalError as u32, Vec::new())).unwrap();
        assert_eq!(h.conn.peer_goaway_last_stream_id(), Some(ids[0]));
        assert_eq!(h.conn.peer_goaway_error(), Some(ErrorCode::InternalError));
    }

    #[test]
    fn test_ping_round_trip_measures_rtt() {
        let mut h = Harness::new();
        let token = h.conn.send_ping().unwrap();
        let ping = h.next_frame();
        assert_eq!(ping.payload, token);
        assert!(!ping.header.flags.has(FrameFlags::ACK));
        assert!(h.conn.last_ping_rtt().is_none());

        h.feed(Frame::ping(*b"stranger", true)).unwrap();
        assert!(h.conn.last_ping_rtt().is_none());
        h.feed(Frame::ping(token, true)).unwrap();
        assert!(h.conn.last_ping_rtt().is_some());
        h.conn.check_liveness().unwrap();
    }

    #[test]
    fn test_unanswered_ping_fails_liveness() {
        let mut h = Harness::new();
        h.conn.set_ack_timeout(Duration::from_millis(1));
        h.conn.send_ping().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        match h.conn.check_liveness() {
            Err(Http2Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected a timeout, got {:?}", other),
        }
    }

    #[test]
    fn test_outstanding_pings_are_bounded() {
        let mut h = Harness::new();
        for _ in 0..MAX_OUTSTANDING_PINGS {
            h.conn.send_ping().unwrap();
        }
        assert!(matches!(h.conn.send_ping(), Err(Http2Error::NotPermitted(_))));
    }

    #[test]
    fn test_keepalive_pings_when_idle() {
        let mut h = Harness::new();
        h.conn.set_keepalive_interval(Some(Duration::ZERO));
        h.conn.poll_keepalive().unwrap();
        assert_eq!(h.next_frame().header.frame_type, FrameType::Ping);

        h.conn.poll_keepalive().unwrap();
        assert_eq!(h.conn.pings_outstanding.len(), 1);
    }

    #[test]
    fn test_settings_ack_timeout_raises_settings_timeout() {
        let mut h = Harness::new();
        h.conn.set_ack_timeout(Duration::from_millis(1));
        h.conn.pending_settings_acks.push_back(Instant::now());
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(protocol_code(h.conn.check_liveness()), ErrorCode::SettingsTimeout);
        h.expect_goaway(0, ErrorCode::SettingsTimeout);
    }

    #[test]
    fn test_settings_ack_clears_pending_timeout() {
        let mut h = Harness::new();
        h.conn.set_ack_timeout(Duration::from_millis(1));
        h.conn.pending_settings_acks.push_back(Instant::now());
        h.feed(Frame::settings_ack()).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        h.conn.check_liveness().unwrap();

        let mut bad_ack = Frame::settings_ack();
        bad_ack.payload = vec![0; 6];
        assert_eq!(protocol_code(h.feed(bad_ack)), ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_settings_validation_errors() {
        let mut h = Harness::new();
        assert_eq!(protocol_code(h.peer_settings(&[(SettingId::InitialWindowSize, 0x8000_0000)])), ErrorCode::FlowControlError);

        let mut h = Harness::new();
        h.peer_settings(&[(SettingId::EnableConnectProtocol, 1)]).unwrap();
        assert_eq!(protocol_code(h.peer_settings(&[(SettingId::EnableConnectProtocol, 0)])), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        h.peer_settings(&[]).unwrap();
        assert_eq!(protocol_code(h.peer_settings(&[(SettingId::NoRfc7540Priorities, 1)])), ErrorCode::ProtocolError);
    }

    #[test]
    fn test_peer_table_size_change_is_signaled_in_next_block() {
        let mut h = Harness::client();
        h.peer_settings(&[(SettingId::HeaderTableSize, 0)]).unwrap();
        h.peer_settings(&[(SettingId::HeaderTableSize, 0)]).unwrap();

        let stream_id = h.conn.create_stream().unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), None).unwrap();
        let headers = h.next_frame();
        assert_eq!(headers.header.frame_type, FrameType::Headers);
        assert_eq!(headers.payload[0], 0x20);
        assert_ne!(headers.payload[1] & 0xe0, 0x20);

        h.peer_decoder.decode(&headers.payload).unwrap();
        assert_eq!(h.peer_decoder.max_dynamic_table_size(), 0);
    }

    #[test]
    fn test_initial_window_change_adjusts_open_streams() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream().unwrap();
        h.peer_settings(&[(SettingId::InitialWindowSize, 100)]).unwrap();
        assert_eq!(h.conn.get_stream(stream_id).unwrap().flow_control().window_size(), 100);
        h.peer_settings(&[(SettingId::InitialWindowSize, 0)]).unwrap();
        assert_eq!(h.conn.get_stream(stream_id).unwrap().flow_control().window_size(), 0);
    }

    #[test]
    fn test_local_settings_fixed_after_handshake() {
        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::EnableConnectProtocol, 1).unwrap();
        h.conn.local_settings_sent = true;
        assert!(matches!(h.conn.set_local_setting(SettingId::HeaderTableSize, 0), Err(Http2Error::NotPermitted(_))));
        assert!(matches!(h.conn.set_local_setting(SettingId::EnableConnectProtocol, 0), Err(Http2Error::NotPermitted(_))));

        h.conn.set_local_setting(SettingId::MaxConcurrentStreams, 7).unwrap();
        let settings = h.next_frame();
        assert_eq!(settings.payload, [&(SettingId::MaxConcurrentStreams as u16).to_be_bytes()[..], &7u32.to_be_bytes()[..]].concat());
        assert_eq!(h.conn.pending_settings_acks.len(), 1);
    }

    #[test]
    fn test_client_stream_closes_after_response() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream().unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), None).unwrap();
        assert_eq!(h.conn.get_stream(stream_id).unwrap().state(), StreamState::HalfClosedLocal);

        let request = h.next_frame();
        assert!(request.header.flags.has(FrameFlags::END_STREAM));
        let decoded = h.peer_decoder.decode(&request.payload).unwrap();
        assert_eq!(decoded.get(":authority"), Some(&"example.com".to_string()));

        let interim = h.block(&[(":status", "103")]);
        h.feed(Frame::headers(stream_id, interim, true, false)).unwrap();
        let response = h.block(&[(":status", "200")]);
        h.feed(Frame::headers(stream_id, response, true, false)).unwrap();
        h.feed(Frame::data(stream_id, b"ok".to_vec(), true)).unwrap();

        let stream = h.conn.get_stream(stream_id).unwrap();
        assert!(stream.is_closed());
        assert_eq!(stream.data(), b"ok");
        assert_eq!(stream.response_headers().last(), Some(&(":status".to_string(), "200".to_string())));
    }

    #[test]
    fn test_request_body_end_stream_closes_send_side() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream().unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), Some(b"payload".to_vec())).unwrap();
        assert_eq!(h.conn.get_stream(stream_id).unwrap().state(), StreamState::HalfClosedLocal);

        assert!(!h.next_frame().header.flags.has(FrameFlags::END_STREAM));
        let data = h.next_frame();
        assert_eq!(data.payload, b"payload");
        assert!(data.header.flags.has(FrameFlags::END_STREAM));
    }

    #[test]
    fn test_extended_connect_requires_peer_setting() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream().unwrap();
        let result = h.conn.send_extended_connect(stream_id, "websocket", "https", "example.com", "/chat", Vec::new());
        assert!(matches!(result, Err(Http2Error::NotPermitted(_))));

        let headers = vec![(":method".to_string(), "CONNECT".to_string()), (":protocol".to_string(), "websocket".to_string())];
        assert!(matches!(h.conn.send_request(stream_id, headers, None), Err(Http2Error::NotPermitted(_))));
        assert_eq!(h.conn.get_stream(stream_id).unwrap().state(), StreamState::Idle);
    }

    #[test]
    fn test_extended_connect_opens_tunnel() {
        let mut h = Harness::client();
        h.peer_settings(&[(SettingId::EnableConnectProtocol, 1)]).unwrap();
        assert!(h.conn.peer_supports_extended_connect());

        let stream_id = h.conn.create_stream().unwrap();
        let extra = vec![("sec-websocket-version".to_string(), "13".to_string()), (":path".to_string(), "/ignored".to_string())];
        h.conn.send_extended_connect(stream_id, "websocket", "https", "example.com", "/chat", extra).unwrap();

        let frame = h.next_frame();
        assert_eq!(frame.header.frame_type, FrameType::Headers);
        assert!(!frame.header.flags.has(FrameFlags::END_STREAM));
        let decoded = h.peer_decoder.decode(&frame.payload).unwrap();
        assert_eq!(decoded.get(":method"), Some(&"CONNECT".to_string()));
        assert_eq!(decoded.get(":protocol"), Some(&"websocket".to_string()));
        assert_eq!(decoded.get(":path"), Some(&"/chat".to_string()));
        assert_eq!(decoded.get("sec-websocket-version"), Some(&"13".to_string()));
        assert_eq!(h.conn.get_stream(stream_id).unwrap().state(), StreamState::Open);

        h.conn.send_data(stream_id, b"frame", false).unwrap();
        assert_eq!(h.next_frame().payload, b"frame");
    }

    #[test]
    fn test_inbound_extended_connect() {
        let connect = [(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/chat"), (":authority", "example.com")];

        let mut h = Harness::new();
        let block = h.block(&connect);
        h.feed(Frame::headers(1, block, true, false)).unwrap();
        h.expect_rst(1, ErrorCode::ProtocolError);

        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::EnableConnectProtocol, 1).unwrap();
        assert!(h.conn.initial_settings().contains(&(SettingId::EnableConnectProtocol as u16, 1)));
        let block = h.block(&connect);
        h.feed(Frame::headers(1, block, true, false)).unwrap();
        assert_eq!(h.conn.get_stream(1).unwrap().state(), StreamState::Open);

        let block = h.block(&[(":method", "GET"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/")]);
        h.feed(Frame::headers(3, block, true, false)).unwrap();
        h.expect_rst(3, ErrorCode::ProtocolError);
        let block = h.block(&[(":method", "CONNECT"), (":protocol", "websocket"), (":authority", "example.com")]);
        h.feed(Frame::headers(5, block, true, false)).unwrap();
        h.expect_rst(5, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_priority_header_and_priority_update() {
        let mut h = Harness::new();
        let block = h.block(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("priority", "u=1, i")]);
        h.feed(Frame::headers(1, block, true, true)).unwrap();
        assert_eq!(h.conn.get_extensible_priority(1), ExtensiblePriority::new(1, true));

        h.feed(Frame::priority_update(1, ExtensiblePriority::new(6, false))).unwrap();
        assert_eq!(h.conn.get_extensible_priority(1), ExtensiblePriority::new(6, false));
    }

    #[test]
    fn test_priority_update_before_headers_takes_precedence() {
        let mut h = Harness::new();
        h.feed(Frame::priority_update(1, ExtensiblePriority::new(0, false))).unwrap();
        let block = h.block(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("priority", "u=5")]);
        h.feed(Frame::headers(1, block, true, true)).unwrap();
        assert_eq!(h.conn.get_extensible_priority(1), ExtensiblePriority::new(0, false));
    }

    #[test]
    fn test_invalid_priority_update_frames() {
        let mut h = Harness::new();
        let mut on_stream = Frame::priority_update(1, ExtensiblePriority::default());
        on_stream.header.stream_id = 1;
        assert_eq!(protocol_code(h.feed(on_stream)), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::priority_update(0, ExtensiblePriority::default()))), ErrorCode::ProtocolError);

        let mut h = Harness::new();
        assert_eq!(protocol_code(h.feed(Frame::new(FrameType::PriorityUpdate, 0, 0, vec![0, 0]))), ErrorCode::FrameSizeError);

        let mut h = Harness::new();
        h.feed(Frame::new(FrameType::PriorityUpdate, 0, 0, vec![0, 0, 0, 1, 0xff, 0xfe])).unwrap();
        h.assert_alive();
    }

    #[test]
    fn test_outbound_extensible_priority() {
        let mut h = Harness::client();
        let stream_id = h.conn.create_stream_with_extensible_priority(ExtensiblePriority::new(1, true)).unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), None).unwrap();
        let request = h.next_frame();
        let decoded = h.peer_decoder.decode(&request.payload).unwrap();
        assert_eq!(decoded.get("priority"), Some(&"u=1, i".to_string()));

        h.conn.set_extensible_priority(stream_id, ExtensiblePriority::new(5, false)).unwrap();
        let update = h.next_frame();
        assert_eq!(update.header.frame_type, FrameType::PriorityUpdate);
        assert_eq!(update.header.stream_id, 0);
        assert_eq!(&update.payload[..4], &stream_id.to_be_bytes());
        assert_eq!(&update.payload[4..], b"u=5");
    }

    #[test]
    fn test_no_rfc7540_priorities_is_advertised_and_priority_frames_ignored() {
        let mut h = Harness::new();
        h.conn.set_local_setting(SettingId::NoRfc7540Priorities, 1).unwrap();
        assert!(h.conn.initial_settings().contains(&(SettingId::NoRfc7540Priorities as u16, 1)));

        h.open_request(1, false).unwrap();
        h.feed(Frame::priority(1, false, 0, 250)).unwrap();
        assert_eq!(h.conn.get_stream_priority(1).unwrap().weight, Priority::default().weight);
        assert!(h.conn.scheduler.extensible_mode());
    }

    #[test]
    fn test_priority_frame_edge_cases() {
        let mut h = Harness::new();
        h.feed(Frame::priority(99, false, 0, 10)).unwrap();
        assert!(h.conn.get_stream_priority(99).is_none());

        h.open_request(1, false).unwrap();
        h.feed(Frame::new(FrameType::Priority, 0, 1, vec![0; 4])).unwrap();
        h.expect_rst(1, ErrorCode::FrameSizeError);

        h.open_request(3, false).unwrap();
        h.feed(Frame::priority(3, false, 3, 10)).unwrap();
        h.expect_rst(3, ErrorCode::ProtocolError);
        h.assert_alive();
    }

    #[test]
    fn test_push_promise_reserves_stream_and_raises_goaway_id() {
        let mut h = Harness::client();
        h.conn.set_push_enabled(true);
        let stream_id = h.conn.create_stream().unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), None).unwrap();

        let block = h.block(&request_headers());
        h.feed(Frame::push_promise(stream_id, 2, block, true)).unwrap();
        assert_eq!(h.conn.highest_peer_stream_id, 2);
        assert_eq!(h.conn.get_stream(2).unwrap().state(), StreamState::ReservedRemote);
        assert_eq!(h.conn.active_peer_stream_count(), 0);

        let response = h.block(&[(":status", "200")]);
        h.feed(Frame::headers(2, response, true, false)).unwrap();
        assert_eq!(h.conn.get_stream(2).unwrap().state(), StreamState::HalfClosedLocal);
        assert_eq!(h.conn.active_peer_stream_count(), 1);

        let block = h.block(&request_headers());
        assert_eq!(protocol_code(h.feed(Frame::push_promise(stream_id, 2, block, true))), ErrorCode::ProtocolError);
    }

    #[test]
    fn test_push_promise_rejected_when_push_disabled() {
        let mut h = Harness::client();
        h.conn.set_local_setting(SettingId::EnablePush, 0).unwrap();
        let stream_id = h.conn.create_stream().unwrap();
        h.conn.send_request(stream_id, request_headers().iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), None).unwrap();
        let block = h.block(&request_headers());
        assert_eq!(protocol_code(h.feed(Frame::push_promise(stream_id, 2, block, true))), ErrorCode::ProtocolError);
    }

    #[test]
    fn test_secure_blob_preserves_shutdown_and_hpack_state() {
        let mut h = Harness::new();
        h.open_request(1, false).unwrap();
        h.open_request(3, false).unwrap();
        h.conn.close().unwrap();

        let (_, blob) = h.conn.to_secure_blob(CompressionAlgorithm::Identity).unwrap();
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_, mut restored) = Http2Connection::from_secure_blob(stream, &blob).unwrap();

        assert_eq!(restored.role(), Role::Server);
        assert_eq!(restored.highest_peer_stream_id, 3);
        assert!(restored.goaway_final_sent);
        assert_eq!(restored.local_goaway_last_stream_id, Some(3));
        assert_eq!(restored.peer_initiated_streams, HashSet::from([1, 3]));
        assert_eq!(restored.decoder.dynamic_table_len(), h.conn.decoder.dynamic_table_len());

        let decoded = restored.decoder.decode(&[0x82, 0x87, 0x84, 0x80 | 62]).unwrap();
        assert_eq!(decoded.get(":authority"), Some(&"example.com".to_string()));
    }
}