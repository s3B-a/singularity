use super::alpn::AlpnProtocol;
use super::error::{ErrorCode, Http2Error, Result};
use super::flow_control::{decode_secure_flow_control, encode_secure_flow_control, FlowControl};
use super::frame::{Frame, FrameFlags, FrameType};
use super::hpack::HpackCodec;
use super::priority::{decode_secure_priority_tree, encode_secure_priority_tree, Priority, PriorityTree};
use super::push::{decode_secure_push_manager, encode_secure_push_manager, PushConfig, PushManager};
use super::scheduler::{decode_secure_priority_scheduler, encode_secure_priority_scheduler, DependencyTreeStats, PriorityScheduler};
use super::settings::{decode_secure_settings, encode_secure_settings, SettingId, Settings};
use super::stream::{decode_secure_http2_stream, encode_secure_http2_stream, Http2Stream};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::tcp::TcpStream;
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_CONNECTION_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_CONNECTION_BLOB_V1";
const HTTP2_CONNECTION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_CONNECTION_BLOB_BINDING_V1";

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

pub struct Http2Connection {
    stream: TcpStream,
    pub streams: HashMap<u32, Http2Stream>,
    next_stream_id: u32,
    local_settings: Settings,
    remote_settings: Settings,
    connection_flow_control: FlowControl,
    encoder: HpackCodec,
    decoder: HpackCodec,
    priority_tree: PriorityTree,
    last_stream_id: u32,
    pub goaway_sent: bool,
    pub goaway_received: bool,
    continuation_state: Option<ContinuationState>,
    scheduler: PriorityScheduler,
    max_frame_size: u32,
    push_manager: PushManager,
    negotiated_protocol: Option<AlpnProtocol>,
}

#[derive(Debug)]
struct ContinuationState {
    stream_id: u32,
    header_block_fragments: Vec<u8>,
    end_stream: bool,
    is_push_promise: bool,
    parent_stream_id: Option<u32>,
}

impl ContinuationState {
    fn new(stream_id: u32, end_stream: bool, is_push_promise: bool) -> Self {
        Self {
            stream_id,
            header_block_fragments: Vec::new(),
            end_stream,
            is_push_promise,
            parent_stream_id: None,
        }
    }
}

impl Http2Connection {
    pub fn new(stream: TcpStream) -> Result<Self> {
        let local_settings = Settings::default();
        let remote_settings = Settings::default();
        let connection_flow_control = FlowControl::new(local_settings.initial_window_size());

        Ok(Self {
            stream,
            streams: HashMap::new(),
            next_stream_id: 1,
            local_settings: local_settings.clone(),
            remote_settings,
            connection_flow_control,
            encoder: HpackCodec::new(local_settings.header_table_size() as usize),
            decoder: HpackCodec::new(local_settings.header_table_size() as usize),
            priority_tree: PriorityTree::new(),
            last_stream_id: 0,
            goaway_sent: false,
            goaway_received: false,
            continuation_state: None,
            scheduler: PriorityScheduler::new(),
            max_frame_size: 16384,
            push_manager: PushManager::with_defaults(),
            negotiated_protocol: None,
        })
    }

    pub fn handshake(&mut self) -> Result<()> {
        self.stream.write_all(CLIENT_PREFACE)?;

        let settings_frame = Frame::settings(vec![
            (SettingId::HeaderTableSize as u16, self.local_settings.header_table_size()),
            (SettingId::EnablePush as u16, if self.local_settings.enable_push() { 1 } else { 0 }),
            (SettingId::MaxConcurrentStreams as u16, self.local_settings.max_concurrent_streams()),
            (SettingId::InitialWindowSize as u16, self.local_settings.initial_window_size()),
            (SettingId::MaxFrameSize as u16, self.local_settings.max_frame_size()),
            (SettingId::MaxHeaderListSize as u16, self.local_settings.max_header_list_size()),
        ]);

        settings_frame.write(&mut self.stream)?;
        self.stream.flush()?;

        let frame = Frame::read(&mut self.stream)?;
        if frame.header.frame_type == FrameType::Settings && !frame.header.flags.has(FrameFlags::ACK) {
            self.handle_settings_frame(&frame)?;
            Frame::settings_ack().write(&mut self.stream)?;
            self.stream.flush()?;
        }

        Ok(())
    }

    pub fn new_with_alpn(stream: TcpStream, negotiated_protocol: Option<AlpnProtocol>) -> Result<Self> {
        if let Some(protocol) = negotiated_protocol {
            if protocol != AlpnProtocol::Http2 {
                return Err(Http2Error::Protocol(
                    ErrorCode::ProtocolError,
                    format!(
                        "HTTP/2 connection requires h2 protocol, got: {}",
                        protocol.name()
                    ),
                ));
            }
        }

        let mut conn = Self::new(stream)?;
        conn.negotiated_protocol = negotiated_protocol;
        Ok(conn)
    }

    pub fn handshake_with_alpn(&mut self, negotiated_protocol: Option<AlpnProtocol>) -> Result<()> {
        if let Some(protocol) = negotiated_protocol {
            if protocol != AlpnProtocol::Http2 {
                return Err(Http2Error::Protocol(
                    ErrorCode::ProtocolError,
                    format!(
                        "ALPN negotiated {:?} but HTTP/2 expected",
                        protocol.name()
                    ),
                ));
            }

            self.negotiated_protocol = Some(protocol);
        }

        self.stream.write_all(CLIENT_PREFACE).map_err(Http2Error::Io)?;

        let settings_frame = Frame::settings(vec![
            (
                SettingId::HeaderTableSize as u16,
                self.local_settings.header_table_size(),
            ),
            (
                SettingId::EnablePush as u16,
                if self.local_settings.enable_push() {
                    1
                } else {
                    0
                },
            ),
            (
                SettingId::MaxConcurrentStreams as u16,
                self.local_settings.max_concurrent_streams(),
            ),
            (
                SettingId::InitialWindowSize as u16,
                self.local_settings.initial_window_size(),
            ),
            (
                SettingId::MaxFrameSize as u16,
                self.local_settings.max_frame_size(),
            ),
            (
                SettingId::MaxHeaderListSize as u16,
                self.local_settings.max_header_list_size(),
            ),
        ]);

        settings_frame.write(&mut self.stream).map_err(Http2Error::Io)?;

        self.stream.flush().map_err(Http2Error::Io)?;
        let frame = Frame::read(&mut self.stream)?;
        if frame.header.frame_type == FrameType::Settings && !frame.header.flags.has(FrameFlags::ACK) {
            self.handle_settings_frame(&frame)?;
            Frame::settings_ack().write(&mut self.stream).map_err(Http2Error::Io)?;
            self.stream.flush().map_err(Http2Error::Io)?;
        }

        Ok(())
    }

    pub fn negotiated_protocol(&self) -> Option<AlpnProtocol> {
        self.negotiated_protocol
    }

    pub fn create_stream(&mut self) -> Result<u32> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let priority = Priority::default();
        let stream = Http2Stream::new(stream_id, self.local_settings.initial_window_size());
        
        self.streams.insert(stream_id, stream);
        self.scheduler.add_stream(stream_id, priority);
        
        Ok(stream_id)
    }

    pub fn create_stream_with_priority(&mut self, priority: Priority) -> Result<u32> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let stream = Http2Stream::new(stream_id, self.local_settings.initial_window_size());
        self.streams.insert(stream_id, stream);
        self.scheduler.add_stream(stream_id, priority);
        
        Ok(stream_id)
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

    pub fn send_request(&mut self, stream_id: u32, headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> Result<()> {
        {
            let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
            stream.set_request_headers(headers.clone());
        }
        
        let headers_map: HashMap<String, String> = headers.into_iter().collect();
        let encoded_headers = self.encoder.encode(&headers_map);
        self.send_headers_with_continuation(stream_id, encoded_headers, body.is_none())?;
        
        {
            let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;
            stream.send_headers()?;
        }
        
        if let Some(body_data) = body {
            self.send_data(stream_id, &body_data, true)?;
        }

        self.stream.flush()?;
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
            let flags = if stream.is_send_complete() && stream.send_buffer_len() == 0 {
                FrameFlags::END_STREAM
            } else {
                0
            };

            let frame = Frame::new(FrameType::Data, flags, stream_id, data);
            frame.write(&mut self.stream)?;
            
            self.connection_flow_control.consume(data_len)?;
            stream.flow_control_mut().consume(data_len)?;
            
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
            let frame = match Frame::read(&mut self.stream) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };

            self.handle_frame(frame)?;
        }

        Ok(())
    }

    pub fn close_stream(&mut self, stream_id: u32) -> Result<()> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset();
        }
        
        self.scheduler.mark_closed(stream_id);
        
        Ok(())
    }

    pub fn get_scheduler_stats(&self) -> DependencyTreeStats {
        self.scheduler.get_tree_stats()
    }

    pub fn get_stream_priority(&self, stream_id: u32) -> Option<Priority> {
        self.scheduler.get_priority(stream_id)
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
        }
    }

    fn handle_window_update(&mut self, stream_id: u32, increment: u32) -> Result<()> {
        if stream_id == 0 {
            self.connection_flow_control.increase(increment)?;
            for (&sid, stream) in &self.streams {
                if stream.send_buffer_len() > 0 && stream.flow_control().window_size() > 0 {
                    self.scheduler.mark_ready(sid, stream.send_buffer_len());
                }
            }
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.flow_control_mut().increase(increment)?;
            if stream.send_buffer_len() > 0 && stream.flow_control().window_size() > 0 {
                self.scheduler.mark_ready(stream_id, stream.send_buffer_len());
            }
        }
        
        self.send_pending_data()?;
        Ok(())
    }

    fn handle_data_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;
        let stream = self.streams.get_mut(&stream_id).ok_or(Http2Error::StreamNotFound(stream_id))?;

        stream.receive_data(frame.payload.clone())?;
        if self.push_manager.get_push(stream_id).is_some() {
            self.push_manager.add_push_data(stream_id, frame.payload.clone())?;
        }

        if frame.header.flags.has(FrameFlags::END_STREAM) {
            stream.receive_end_stream()?;
            if self.push_manager.get_push(stream_id).is_some() {
                self.push_manager.complete_push(stream_id)?;
            }
        }

        let data_len = frame.payload.len();
        if data_len > 0 {
            Frame::window_update(stream_id, data_len as u32).write(&mut self.stream)?;
            Frame::window_update(0, data_len as u32).write(&mut self.stream)?;
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

        state.header_block_fragments.extend_from_slice(&frame.payload);
        if frame.header.flags.has(FrameFlags::END_HEADERS) {
            let headers_map = self.decoder.decode(&state.header_block_fragments).map_err(|e| {
                Http2Error::Protocol(
                    ErrorCode::CompressionError,
                    format!("HPACK decode error: {}", e),
                )
            })?;
            
            let headers: Vec<(String, String)> = headers_map.into_iter().collect();

            if state.is_push_promise {
                let parent_id = state.parent_stream_id.unwrap_or(0);
                self.process_push_promise(parent_id, state.stream_id, headers)?;
            } else {
                self.process_received_headers(state.stream_id, headers, state.end_stream)?;
            }

            self.continuation_state = None;
        } else {
            self.continuation_state = Some(state);
        }

        Ok(())
    }

    fn handle_headers_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;
        let end_stream = frame.header.flags.has(FrameFlags::END_STREAM);
        let end_headers = frame.header.flags.has(FrameFlags::END_HEADERS);
        if end_headers {
            let headers_map = self.decoder.decode(&frame.payload).map_err(|e| {
                Http2Error::Protocol(
                    ErrorCode::CompressionError,
                    format!("HPACK decode error: {}", e),
                )
            })?;

            let headers: Vec<(String, String)> = headers_map.into_iter().collect();
            if self.push_manager.get_push(stream_id).is_some() {
                self.push_manager.add_push_headers(stream_id, headers.clone())?;
            }

            self.process_received_headers(stream_id, headers, end_stream)?;
        } else {
            let mut state = ContinuationState::new(stream_id, end_stream, false);
            state.header_block_fragments.extend_from_slice(&frame.payload);
            self.continuation_state = Some(state);
        }

        Ok(())
    }

    fn process_received_headers(&mut self, stream_id: u32, headers: Vec<(String, String)>, end_stream: bool) -> Result<()> {
        let header_size: usize = headers.iter().map(|(name, value)| {
            name.len() + value.len() + 32
        }).sum();

        if header_size > self.local_settings.max_header_list_size() as usize {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Header list size exceeds maximum".to_string(),
            ));
        }

        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            Http2Stream::new(stream_id, self.local_settings.initial_window_size())
        });

        stream.receive_headers()?;
        stream.add_response_headers(headers);
        if end_stream {
            stream.receive_end_stream()?;
        }

        Ok(())
    }

    fn handle_priority_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() != 5 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid PRIORITY frame size".to_string(),
            ));
        }

        let priority = super::priority::Priority::parse(&frame.payload);
        self.priority_tree.set_priority(frame.header.stream_id, priority);
        
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
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset();
        }

        if let Some(ref state) = self.continuation_state {
            if state.stream_id == stream_id {
                self.continuation_state = None;
            }
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
            return Ok(());
        }

        if frame.payload.len() % 6 != 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid SETTINGS frame size".to_string(),
            ));
        }

        let settings = Settings::parse(&frame.payload)
            .map_err(|e| Http2Error::Protocol(ErrorCode::ProtocolError, e))?;

        let old_initial_window = self.remote_settings.initial_window_size();
        let new_initial_window = settings.initial_window_size();
        self.remote_settings = settings;

        let new_table_size = self.remote_settings.header_table_size() as usize;
        self.encoder = HpackCodec::new(new_table_size);

        let window_delta = new_initial_window as i64 - old_initial_window as i64;
        if window_delta != 0 {
            for stream in self.streams.values_mut() {
                if window_delta > 0 {
                    stream.flow_control_mut().increase(window_delta as u32)?;
                } else {
                    let decrease = (-window_delta) as u32;
                    if stream.flow_control_mut().window_size() >= decrease as i32 {
                        stream.flow_control_mut().consume(decrease as usize)?;
                    }
                }
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
        if frame.payload.len() < 4 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid PUSH_PROMISE frame size".to_string(),
            ));
        }

        let promised_stream_id = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & 0x7FFFFFFF;

        let header_block = &frame.payload[4..];
        let end_headers = frame.header.flags.has(FrameFlags::END_HEADERS);
        if end_headers {
            let headers_map = self.decoder.decode(header_block).map_err(|e| {
                Http2Error::Protocol(
                    ErrorCode::CompressionError,
                    format!("HPACK decode error: {}", e),
                )
            })?;

            let headers: Vec<(String, String)> = headers_map.into_iter().collect();
            self.process_push_promise(frame.header.stream_id, promised_stream_id, headers)?;
        } else {
            let mut state = ContinuationState::new(promised_stream_id, false, true);
            state.parent_stream_id = Some(frame.header.stream_id);
            state.header_block_fragments.extend_from_slice(header_block);
            self.continuation_state = Some(state);
        }

        Ok(())
    }

    fn process_push_promise(&mut self, parent_stream_id: u32, promised_stream_id: u32, headers: Vec<(String, String)>) -> Result<()> {
        let accept = self.push_manager.handle_push_promise(parent_stream_id, promised_stream_id, headers.clone())?;
        if !accept {
            let frame = Frame::rst_stream(promised_stream_id, ErrorCode::Cancel as u32);
            frame.write(&mut self.stream)?;
            self.stream.flush()?;
            return Ok(());
        }

        let stream = Http2Stream::new(promised_stream_id, self.local_settings.initial_window_size());
        self.streams.insert(promised_stream_id, stream);

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

        if !frame.header.flags.has(FrameFlags::ACK) {
            let mut data = [0u8; 8];
            data.copy_from_slice(&frame.payload);
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
        ]) & 0x7FFFFFFF;

        let _error_code = u32::from_be_bytes([
            frame.payload[4],
            frame.payload[5],
            frame.payload[6],
            frame.payload[7],
        ]);

        self.last_stream_id = last_stream_id;
        self.goaway_received = true;

        let streams_to_close: Vec<u32> = self.streams.keys().filter(|&&id| {
            id > last_stream_id
        }).copied().collect();

        for stream_id in streams_to_close {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.reset();
            }
        }

        Ok(())
    }

    fn handle_window_update_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() != 4 {
            return Err(Http2Error::Protocol(
                ErrorCode::FrameSizeError,
                "Invalid WINDOW_UPDATE frame".to_string(),
            ));
        }

        let increment = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & 0x7FFFFFFF;

        if frame.header.stream_id == 0 {
            self.connection_flow_control.increase(increment)?;
        } else if let Some(stream) = self.streams.get_mut(&frame.header.stream_id) {
            stream.flow_control_mut().increase(increment)?;
        }

        Ok(())
    }

    fn handle_window_update_frame_with_validation(&mut self, frame: &Frame) -> Result<()> {
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

        if increment == 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "WINDOW_UPDATE increment is 0".to_string(),
            ));
        }

        if frame.header.stream_id == 0 {
            self.connection_flow_control.increase(increment)?;
        } else if let Some(stream) = self.streams.get_mut(&frame.header.stream_id) {
            stream.flow_control_mut().increase(increment)?;
        }

        Ok(())
    }

    pub fn get_stream(&self, stream_id: u32) -> Option<&Http2Stream> {
        self.streams.get(&stream_id)
    }

    pub fn get_stream_mut(&mut self, stream_id: u32) -> Option<&mut Http2Stream> {
        self.streams.get_mut(&stream_id)
    }

    pub fn close(&mut self) -> Result<()> {
        if !self.goaway_sent {
            let frame = Frame::goaway(self.last_stream_id, ErrorCode::NoError as u32, Vec::new());
            frame.write(&mut self.stream)?;
            self.stream.flush()?;
            self.goaway_sent = true;
        }

        Ok(())
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

    lines.push(format!("next-stream-id={}", connection.next_stream_id));
    lines.push(format!("last-stream-id={}", connection.last_stream_id));
    lines.push(format!("goaway-sent={}", connection.goaway_sent));
    lines.push(format!("goaway-received={}", connection.goaway_received));
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

        Some(ContinuationState {
            stream_id,
            header_block_fragments: header_block,
            end_stream,
            is_push_promise,
            parent_stream_id,
        })
    } else {
        None
    };

    let encoder = HpackCodec::new(local_settings.header_table_size() as usize);
    let decoder = HpackCodec::new(local_settings.header_table_size() as usize);

    Ok(Http2Connection {
        stream,
        streams,
        next_stream_id,
        local_settings,
        remote_settings,
        connection_flow_control,
        encoder,
        decoder,
        priority_tree,
        last_stream_id,
        goaway_sent,
        goaway_received,
        continuation_state,
        scheduler,
        max_frame_size,
        push_manager,
        negotiated_protocol,
    })
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

    #[test]
    fn test_continuation_state() {
        let state = ContinuationState::new(1, true, false);
        assert_eq!(state.stream_id, 1);
        assert!(state.end_stream);
        assert!(!state.is_push_promise);
        assert!(state.header_block_fragments.is_empty());
    }
}