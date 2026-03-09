use super::error::{Error, ErrorCode, Result};
use super::frame::Frame;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub type StreamId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    ClientBidirectional,
    ServerBidirectional,
    ClientUnidirectional,
    ServerUnidirectional,
}

impl StreamType {
    pub fn from_id(id: StreamId) -> Self {
        match id & 0x03 {
            0x00 => StreamType::ClientBidirectional,
            0x01 => StreamType::ServerBidirectional,
            0x02 => StreamType::ClientUnidirectional,
            0x03 => StreamType::ServerUnidirectional,
            _ => unreachable!(),
        }
    }

    pub fn is_bidirectional(&self) -> bool {
        matches!(self, StreamType::ClientBidirectional | StreamType::ServerBidirectional)
    }

    pub fn is_unidirectional(&self) -> bool {
        !self.is_bidirectional()
    }

    pub fn is_client_initiated(&self) -> bool {
        matches!(self, StreamType::ClientBidirectional | StreamType::ClientUnidirectional)
    }

    pub fn is_server_initiated(&self) -> bool {
        matches!(self, StreamType::ServerBidirectional | StreamType::ServerUnidirectional)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    SendClosed,
    ReceivedClosed,
    Closed,
    ResetSent,
    ResetReceived,
}

impl StreamState {
    pub fn can_send(&self) -> bool {
        matches!(self, StreamState::Open)
    }

    pub fn can_receive(&self) -> bool {
        matches!(self, StreamState::Open | StreamState::SendClosed)
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, StreamState::Closed | StreamState::ResetSent | StreamState::ResetReceived)
    }
}

#[derive(Debug, Clone)]
struct DataChunk {
    offset: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct Stream {
    id: StreamId,
    stream_type: StreamType,
    state: StreamState,
    send_buffer: VecDeque<u8>,
    send_offset: u64,
    send_max_offset: u64,
    send_final_offset: Option<u64>,
    receive_buffer: VecDeque<u8>,
    receive_offset: u64,
    receive_max_offset: u64,
    receive_final_offset: Option<u64>,
    receive_chunks: BTreeMap<u64, DataChunk>,
    fin_queued: bool,
    fin_sent: bool,
    fin_received: bool,
    priority: u8,
    error_code: Option<u64>,
}

impl Stream {
    pub fn new(id: StreamId, max_send: u64, max_recieved: u64) -> Self {
        Self {
            id,
            stream_type: StreamType::from_id(id),
            state: StreamState::Open,
            send_buffer: VecDeque::new(),
            send_offset: 0,
            send_max_offset: max_send,
            send_final_offset: None,
            receive_buffer: VecDeque::new(),
            receive_offset: 0,
            receive_max_offset: max_recieved,
            receive_final_offset: None,
            receive_chunks: BTreeMap::new(),
            fin_queued: false,
            fin_sent: false,
            fin_received: false,
            priority: 128,
            error_code: None,
        }
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.state.can_send() {
            return Err(Error::InvalidStreamState);
        }

        if self.fin_queued {
            return Err(Error::InvalidOperation("FIN already queued".to_string()));
        }

        let available = (self.send_max_offset - self.send_offset - self.send_buffer.len() as u64) as usize;
        let to_write = data.len().min(available);
        if to_write == 0 {
            return Err(Error::FlowControl("Send window full".to_string()));
        }

        self.send_buffer.extend(&data[..to_write]);

        Ok(to_write)
    }

    pub fn write_fin(&mut self, data: &[u8]) -> Result<usize> {
        let written = self.write(data)?;
        self.fin_queued = true;

        Ok(written)
    }

    pub fn close_send(&mut self) -> Result<()> {
        if !self.state.can_send() {
            return Err(Error::InvalidStreamState);
        }

        self.fin_queued = true;

        Ok(())
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if !self.state.can_receive() {
            if self.fin_received {
                return Ok(0); // EOF
            }

            return Err(Error::InvalidStreamState);
        }

        let to_read = buffer.len().min(self.receive_buffer.len());
        for i in 0..to_read {
            buffer[i] = self.receive_buffer.pop_front().unwrap();
        }

        Ok(to_read)
    }

    pub fn readable(&self) -> usize {
        self.receive_buffer.len()
    }

    pub fn writable(&self) -> usize {
        if !self.state.can_send() || self.fin_queued {
            return 0;
        }

        (self.send_max_offset - self.send_offset - self.send_buffer.len() as u64) as usize
    }

    pub fn has_data_to_send(&self) -> bool {
        !self.send_buffer.is_empty() || (self.fin_queued && !self.fin_sent)
    }

    pub fn generate_frame(&mut self, max_data: usize) -> Result<Option<Frame>> {
        if !self.has_data_to_send() {
            return Ok(None);
        }

        let available = self.send_buffer.len().min(max_data);
        if available == 0 && !self.fin_queued {
            return Ok(None);
        }

        let mut data = Vec::with_capacity(available);
        for _ in 0..available {
            data.push(self.send_buffer.pop_front().unwrap());
        }

        let fin = self.fin_queued && self.send_buffer.is_empty();
        if fin {
            self.fin_sent = true;
            self.send_final_offset = Some(self.send_offset + data.len() as u64);
            self.update_state_after_send();
        }

        let frame = Frame::Stream {
            stream_id: self.id,
            offset: self.send_offset,
            data: data.clone(),
            fin,
        };

        self.send_offset += data.len() as u64;

        Ok(Some(frame))
    }

    pub fn process_frame(&mut self, offset: u64, data: Vec<u8>, fin: bool) -> Result<()> {
        if !self.state.can_receive() {
            return Err(Error::InvalidStreamState);
        }

        if let Some(final_offset) = self.receive_final_offset {
            if fin && offset + data.len() as u64 != final_offset {
                return Err(Error::transport(ErrorCode::FinalSizeError, "FIN offset mismatch"));
            }

            if offset + data.len() as u64 > final_offset {
                return Err(Error::transport(ErrorCode::FinalSizeError, "Data exceeds final offset"));
            }
        }

        if offset + data.len() as u64 > self.receive_max_offset {
            return Err(Error::transport(ErrorCode::FlowControlError, "Receive window exceeded"));
        }

        if fin {
            self.receive_final_offset = Some(offset + data.len() as u64);
            self.fin_received = true;
        }

        if offset == self.receive_offset {
            self.receive_buffer.extend(&data);
            self.receive_offset += data.len() as u64;
            self.process_queued_chunks();
            if fin && self.receive_buffer.is_empty() {
                self.update_state_after_receive();
            }
        } else if offset > self.receive_offset {
            self.receive_chunks.insert(offset, DataChunk { offset, data, });
        }

        Ok(())
    }

    pub fn reset(&mut self, error_code: u64) -> Result<()> {
        if self.state.is_closed() {
            return Ok(());
        }

        self.error_code = Some(error_code);
        self.state = StreamState::ResetSent;
        self.send_buffer.clear();
        self.receive_buffer.clear();
        self.receive_chunks.clear();

        Ok(())
    }

    pub fn handle_reset(&mut self, error_code: u64) -> Result<()> {
        self.error_code = Some(error_code);
        self.state = StreamState::ResetReceived;
        self.send_buffer.clear();
        self.receive_buffer.clear();
        self.receive_chunks.clear();

        Ok(())
    }

    pub fn handle_stop_sending(&mut self, error_code: u64) -> Result<()> {
        self.reset(error_code)
    }

    pub fn update_send_max_offset(&mut self, new_max: u64) -> Result<()> {
        if new_max < self.send_max_offset {
            return Err(Error::transport(ErrorCode::FlowControlError, "Send max offset decreased"));
        }

        self.send_max_offset = new_max;
        Ok(())
    }

    pub fn update_receive_max_offset(&mut self, new_max: u64) {
        self.receive_max_offset = new_max;
    }

    pub fn send_offset(&self) -> u64 {
        self.send_offset
    }

    pub fn receive_offset(&self) -> u64 {
        self.receive_offset
    }

    pub fn send_max_offset(&self) -> u64 {
        self.send_max_offset
    }

    pub fn receive_max_offset(&self) -> u64 {
        self.receive_max_offset
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_closed()
    }

    pub fn fin_sent(&self) -> bool {
        self.fin_sent
    }

    pub fn fin_received(&self) -> bool {
        self.fin_received
    }

    fn process_queued_chunks(&mut self) {
        while let Some((&offset, _)) = self.receive_chunks.iter().next() {
            if offset != self.receive_offset {
                break;
            }

            if let Some(chunk) = self.receive_chunks.remove(&offset) {
                self.receive_buffer.extend(&chunk.data);
                self.receive_offset += chunk.data.len() as u64;
            }
        }

        if self.fin_received {
            if let Some(final_offset) = self.receive_final_offset {
                if self.receive_offset >= final_offset {
                    self.update_state_after_send();
                }
            }
        }
    }

    fn update_state_after_send(&mut self) {
        if self.fin_sent {
            match self.state {
                StreamState::Open => {
                    self.state = StreamState::SendClosed;
                }
                StreamState::ReceivedClosed => {
                    self.state = StreamState::Closed;
                }
                _ => {}
            }
        }
    }

    fn update_state_after_receive(&mut self) {
        if self.fin_received {
            match self.state {
                StreamState::Open => {
                    self.state = StreamState::ReceivedClosed;
                }
                StreamState::SendClosed => {
                    self.state = StreamState::Closed;
                }
                _ => {}
            }
        }
    }

    pub fn error_code(&self) -> Option<u64> {
        self.error_code
    }
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamType::ClientBidirectional => write!(f, "ClientBidi"),
            StreamType::ServerBidirectional => write!(f, "ServerBidi"),
            StreamType::ClientUnidirectional => write!(f, "ClientUni"),
            StreamType::ServerUnidirectional => write!(f, "ServerUni"),
        }
    }
}

impl fmt::Display for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamState::Open => write!(f, "Open"),
            StreamState::SendClosed => write!(f, "SendClosed"),
            StreamState::ReceivedClosed => write!(f, "ReceivedClosed"),
            StreamState::Closed => write!(f, "Closed"),
            StreamState::ResetSent => write!(f, "ResetSent"),
            StreamState::ResetReceived => write!(f, "ResetReceived"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_type_from_id() {
        assert_eq!(StreamType::from_id(0), StreamType::ClientBidirectional);
        assert_eq!(StreamType::from_id(1), StreamType::ServerBidirectional);
        assert_eq!(StreamType::from_id(2), StreamType::ClientUnidirectional);
        assert_eq!(StreamType::from_id(3), StreamType::ServerUnidirectional);
        assert_eq!(StreamType::from_id(4), StreamType::ClientBidirectional);
    }

    #[test]
    fn test_stream_type_properties() {
        assert!(StreamType::ClientBidirectional.is_bidirectional());
        assert!(StreamType::ClientBidirectional.is_client_initiated());
        assert!(!StreamType::ClientBidirectional.is_unidirectional());

        assert!(StreamType::ServerUnidirectional.is_unidirectional());
        assert!(StreamType::ServerUnidirectional.is_server_initiated());
        assert!(!StreamType::ServerUnidirectional.is_bidirectional());
    }

    #[test]
    fn test_stream_write_read() {
        let mut stream = Stream::new(0, 1000, 1000);

        let data = b"hello world";
        let written = stream.write(data).unwrap();
        assert_eq!(written, data.len());

        let frame = stream.generate_frame(1000).unwrap().unwrap();
        match frame {
            Frame::Stream { stream_id, offset, data: frame_data, fin } => {
                assert_eq!(stream_id, 0);
                assert_eq!(offset, 0);
                assert_eq!(frame_data, data);
                assert!(!fin);

                stream.process_frame(offset, frame_data, fin).unwrap();
            }
            _ => panic!("Expected Stream frame"),
        }

        let mut buf = vec![0u8; 100];
        let read = stream.read(&mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }

    #[test]
    fn test_stream_fin() {
        let mut stream = Stream::new(0, 1000, 1000);

        stream.write_fin(b"data").unwrap();
        assert!(stream.fin_queued);

        let frame = stream.generate_frame(1000).unwrap().unwrap();
        match frame {
            Frame::Stream { fin, .. } => {
                assert!(fin);
                assert!(stream.fin_sent);
            }
            _ => panic!("Expected Stream frame"),
        }

        assert_eq!(stream.state, StreamState::SendClosed);
    }

    #[test]
    fn test_stream_flow_control() {
        let mut stream = Stream::new(0, 100, 100);

        let data = vec![0u8; 200];
        let result = stream.write(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn test_stream_out_of_order() {
        let mut stream = Stream::new(0, 1000, 1000);

        stream.process_frame(10, vec![3, 4, 5], false).unwrap();
        assert_eq!(stream.readable(), 0);

        stream.process_frame(0, vec![0, 1, 2], false).unwrap();
        assert_eq!(stream.readable(), 3);

        stream.process_frame(3, vec![6, 7, 8, 9], false).unwrap();
        assert_eq!(stream.readable(), 13);
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = Stream::new(0, 1000, 1000);

        stream.write(b"data").unwrap();
        stream.reset(42).unwrap();

        assert_eq!(stream.state, StreamState::ResetSent);
        assert_eq!(stream.error_code(), Some(42));
        assert!(stream.send_buffer.is_empty());
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(0, 1000, 1000);
        assert_eq!(stream.state, StreamState::Open);

        stream.close_send().unwrap();
        stream.generate_frame(1000).unwrap();
        assert_eq!(stream.state, StreamState::SendClosed);

        stream.process_frame(0, vec![], true).unwrap();
        assert_eq!(stream.state, StreamState::Closed);
    }

    #[test]
    fn test_stream_priority() {
        let mut stream = Stream::new(0, 1000, 1000);
        assert_eq!(stream.priority(), 128);

        stream.set_priority(200);
        assert_eq!(stream.priority(), 200);
    }
}