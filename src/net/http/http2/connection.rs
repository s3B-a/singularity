use super::error::{ErrorCode, Http2Error, Result};
use super::alpn::AlpnProtocol;
use super::flow_control::FlowControl;
use super::frame::{Frame, FrameFlags, FrameType};
use super::hpack::HpackCodec;
use super::priority::{Priority, PriorityTree};
use super::push::{PushManager, PushConfig};
use super::settings::{Settings, SettingId};
use super::scheduler::{PriorityScheduler, DependencyTreeStats};
use super::stream::Http2Stream;
use crate::net::tcp::TcpStream;
use std::collections::HashMap;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
        
        let connection_flow_control = FlowControl::new(
            local_settings.initial_window_size()
        );

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
        if frame.header.frame_type == FrameType::Settings 
            && !frame.header.flags.has(FrameFlags::ACK) {
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

        Self::new(stream)
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
        }

        self.stream.write_all(CLIENT_PREFACE).map_err(|e| {
            Http2Error::Io(e)
        })?;

        let settings_frame = Frame::settings(vec![
            (
                SettingId::HeaderTableSize as u16,
                self.local_settings.header_table_size(),
            ),
            (
                SettingId::EnablePush as u16,
                if self.local_settings.enable_push() { 1 } else { 0 },
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

        settings_frame.write(&mut self.stream).map_err(|e| {
            Http2Error::Io(e)
        })?;

        self.stream.flush().map_err(|e| Http2Error::Io(e))?;
        let frame = Frame::read(&mut self.stream)?;
        if frame.header.frame_type == FrameType::Settings && !frame.header.flags.has(FrameFlags::ACK) {
            self.handle_settings_frame(&frame)?;
            Frame::settings_ack()
                .write(&mut self.stream)
                .map_err(|e| Http2Error::Io(e))?;
            self.stream.flush().map_err(|e| Http2Error::Io(e))?;
        }

        Ok(())
    }

    /// Get negotiated ALPN protocol
    pub fn negotiated_protocol(&self) -> Option<AlpnProtocol> {
        // Would need to track this in the connection struct
        // For now, HTTP/2 connection implies h2 protocol
        Some(AlpnProtocol::Http2)
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
            let stream = self.streams.get_mut(&stream_id)
                .ok_or(Http2Error::StreamNotFound(stream_id))?;
            stream.set_request_headers(headers.clone());
        }
        
        let headers_map: HashMap<String, String> = headers.into_iter().collect();
        let encoded_headers = self.encoder.encode(&headers_map);
        self.send_headers_with_continuation(stream_id, encoded_headers, body.is_none())?;
        
        {
            let stream = self.streams.get_mut(&stream_id)
                .ok_or(Http2Error::StreamNotFound(stream_id))?;
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
                    format!("CONTINUATION on wrong stream: expected {}, got {}", 
                        state.stream_id, frame.header.stream_id),
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
        } else {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.flow_control_mut().increase(increment)?;
                
                if stream.send_buffer_len() > 0 && stream.flow_control().window_size() > 0 {
                    self.scheduler.mark_ready(stream_id, stream.send_buffer_len());
                }
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
            Frame::window_update(stream_id, data_len as u32)
                .write(&mut self.stream)?;
            Frame::window_update(0, data_len as u32)
                .write(&mut self.stream)?;
            self.stream.flush()?;
        }

        Ok(())
    }

    fn handle_continuation_frame(&mut self, frame: &Frame) -> Result<()> {
        let mut state = self.continuation_state.take()
            .ok_or_else(|| Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "CONTINUATION without HEADERS/PUSH_PROMISE".to_string(),
            ))?;

        state.header_block_fragments.extend_from_slice(&frame.payload);
        if frame.header.flags.has(FrameFlags::END_HEADERS) {
            let headers_map = self.decoder.decode(&state.header_block_fragments)
                .map_err(|e| Http2Error::Protocol(
                    ErrorCode::CompressionError,
                    format!("HPACK decode error: {}", e),
                ))?;
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
            let headers_map = self.decoder.decode(&frame.payload)
                .map_err(|e| Http2Error::Protocol(
                    ErrorCode::CompressionError,
                    format!("HPACK decode error: {}", e),
                ))?;
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
        let header_size: usize = headers.iter()
            .map(|(name, value)| name.len() + value.len() + 32)
            .sum();

        if header_size > self.local_settings.max_header_list_size() as usize {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Header list size exceeds maximum".to_string(),
            ));
        }

        let stream = self.streams.entry(stream_id)
            .or_insert_with(|| Http2Stream::new(
                stream_id,
                self.local_settings.initial_window_size(),
            ));

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
            return Err(Http2Error::Protocol(ErrorCode::FrameSizeError, "Invalid PUSH_PROMISE frame size".to_string()));
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
            let headers_map = self.decoder.decode(header_block)
                .map_err(|e| Http2Error::Protocol(ErrorCode::CompressionError, format!("HPACK decode error: {}", e)))?;
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

        let stream = Http2Stream::new(promised_stream_id,self.local_settings.initial_window_size());
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
        let streams_to_close: Vec<u32> = self.streams.keys()
            .filter(|&&id| id > last_stream_id)
            .copied()
            .collect();

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
        } else {
            if let Some(stream) = self.streams.get_mut(&frame.header.stream_id) {
                stream.flow_control_mut().increase(increment)?;
            }
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
            let error_code = if frame.header.stream_id == 0 {
                ErrorCode::ProtocolError
            } else {
                ErrorCode::ProtocolError
            };

            return Err(Http2Error::Protocol(
                error_code,
                "WINDOW_UPDATE increment is 0".to_string(),
            ));
        }

        if frame.header.stream_id == 0 {
            self.connection_flow_control.increase(increment)?;
        } else {
            if let Some(stream) = self.streams.get_mut(&frame.header.stream_id) {
                stream.flow_control_mut().increase(increment)?;
            }
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