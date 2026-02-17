use super::flow_control::FlowControl;
use super::priority::Priority;
use super::error::{ErrorCode, Http2Error, Result};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Debug)]
pub struct Http2Stream {
    id: u32,
    state: StreamState,
    flow_control: FlowControl,
    priority: Priority,
    pub send_buffer: VecDeque<Vec<u8>>,
    recv_buffer: Vec<u8>,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    trailers: Vec<(String, String)>,
    pub headers_received: bool,
    headers_sent: bool,
    end_stream_received: bool,
    pub end_stream_sent: bool,
}

impl Http2Stream {
    pub fn new(id: u32, initial_window_size: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            flow_control: FlowControl::new(initial_window_size),
            priority: Priority::default(),
            send_buffer: VecDeque::new(),
            recv_buffer: Vec::new(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            trailers: Vec::new(),
            headers_received: false,
            headers_sent: false,
            end_stream_received: false,
            end_stream_sent: false,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    pub fn is_readable(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedLocal
        )
    }

    pub fn flow_control(&self) -> &FlowControl {
        &self.flow_control
    }

    pub fn flow_control_mut(&mut self) -> &mut FlowControl {
        &mut self.flow_control
    }

    pub fn priority(&self) -> &Priority {
        &self.priority
    }

    pub fn set_priority(&mut self, priority: Priority) {
        self.priority = priority;
    }

    pub fn set_request_headers(&mut self, headers: Vec<(String, String)>) {
        self.request_headers = headers;
    }

    pub fn request_headers(&self) -> &[(String, String)] {
        &self.request_headers
    }

    pub fn add_response_headers(&mut self, headers: Vec<(String, String)>) {
        self.response_headers.extend(headers);
        self.headers_received = true;
    }

    pub fn response_headers(&self) -> &[(String, String)] {
        &self.response_headers
    }

    pub fn add_trailers(&mut self, trailers: Vec<(String, String)>) {
        self.trailers.extend(trailers);
    }

    pub fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty()
    }

    pub fn pending_data_len(&self) -> usize {
        self.send_buffer.len()
    }

    pub fn data(&self) -> &[u8] {
        &self.recv_buffer
    }

    pub fn can_receive(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedLocal
        )
    }

    pub fn all_response_headers(&self) -> Vec<(String, String)> {
        let mut headers = self.response_headers.clone();
        headers.extend(self.trailers.clone());
        headers
    }

    pub fn clear_received_data(&mut self) {
        self.recv_buffer.clear();
    }

    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    pub fn queue_data(&mut self, data: Vec<u8>) -> Result<()> {
        if !self.is_writable() {
            return Err(Http2Error::Protocol(
                ErrorCode::StreamClosed,
                "Cannot write to closed stream".to_string(),
            ));
        }
        self.send_buffer.push_back(data);
        Ok(())
    }

    pub fn next_data_chunk(&mut self, max_size: usize) -> Option<Vec<u8>> {
        if let Some(data) = self.send_buffer.front_mut() {
            let available = self.flow_control.window_size().max(0) as usize;
            let size = available.min(max_size).min(data.len());
            if size == 0 {
                return None;
            }

            let chunk = data.drain(..size).collect();
            if data.is_empty() {
                self.send_buffer.pop_front();
            }

            self.flow_control.consume(size).ok()?;
            Some(chunk)
        } else {
            None
        }
    }

    pub fn receive_data(&mut self, data: Vec<u8>) -> Result<()> {
        if !self.is_readable() {
            return Err(Http2Error::Protocol(
                ErrorCode::StreamClosed,
                "Cannot read from closed stream".to_string(),
            ));
        }
        self.recv_buffer.extend(data);
        Ok(())
    }

    pub fn take_received_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.recv_buffer)
    }

    pub fn receive_headers(&mut self) -> Result<()> {
        match self.state {
            StreamState::Idle => {
                self.state = StreamState::Open;
                Ok(())
            }
            StreamState::ReservedRemote => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            _ => Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Invalid state for receiving headers".to_string(),
            )),
        }
    }

    pub fn send_headers(&mut self) -> Result<()> {
        match self.state {
            StreamState::Idle => {
                self.state = StreamState::Open;
                self.headers_sent = true;
                Ok(())
            }
            StreamState::ReservedLocal => {
                self.state = StreamState::HalfClosedRemote;
                self.headers_sent = true;
                Ok(())
            }
            _ => Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Invalid state for sending headers".to_string(),
            )),
        }
    }

    pub fn receive_end_stream(&mut self) -> Result<()> {
        self.end_stream_received = true;
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            StreamState::HalfClosedLocal => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(Http2Error::Protocol(
                ErrorCode::StreamClosed,
                "Stream already closed".to_string(),
            )),
        }
    }

    pub fn send_end_stream(&mut self) -> Result<()> {
        self.end_stream_sent = true;
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(Http2Error::Protocol(
                ErrorCode::StreamClosed,
                "Stream already closed".to_string(),
            )),
        }
    }

    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
        self.send_buffer.clear();
        self.recv_buffer.clear();
    }
}