use super::error::{Error, ErrorCode, Result};
use super::frame::Frame;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const STREAM_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_STREAM_BLOB_V1";
const STREAM_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_STREAM_BLOB_BINDING_V1";

pub type StreamId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureStreamBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

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
                return Ok(0);
            }

            return Err(Error::InvalidStreamState);
        }

        let to_read = buffer.len().min(self.receive_buffer.len());
        for b in buffer.iter_mut().take(to_read) {
            *b = self.receive_buffer.pop_front().unwrap();
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
            self.receive_chunks.insert(offset, DataChunk { offset, data });
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

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureStreamBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_stream(self)?;
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure stream nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_stream_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureStreamBlobMeta {
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
            magic = STREAM_BLOB_MAGIC,
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

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureStreamBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_stream_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureStreamBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_stream_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid stream nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid stream digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid stream tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_stream_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure stream blob tag verification failed",
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
                    "stream raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure stream blob digest verification failed",
            ));
        }

        let stream = deserialize_stream(&raw_payload)?;
        Ok((meta, stream))
    }
}

pub fn select_secure_stream_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_stream(stream: &Stream, algorithm: CompressionAlgorithm) -> io::Result<(SecureStreamBlobMeta, Vec<u8>)> {
    stream.to_secure_blob(algorithm)
}

pub fn encode_secure_stream_auto(stream: &Stream, accept_encoding: &str) -> io::Result<(SecureStreamBlobMeta, Vec<u8>)> {
    stream.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_stream(data: &[u8]) -> io::Result<(SecureStreamBlobMeta, Stream)> {
    Stream::from_secure_blob(data)
}

fn stream_type_label(stream_type: StreamType) -> &'static str {
    match stream_type {
        StreamType::ClientBidirectional => "ClientBidirectional",
        StreamType::ServerBidirectional => "ServerBidirectional",
        StreamType::ClientUnidirectional => "ClientUnidirectional",
        StreamType::ServerUnidirectional => "ServerUnidirectional",
    }
}

fn parse_stream_type(value: &str) -> io::Result<StreamType> {
    match value {
        "ClientBidirectional" => Ok(StreamType::ClientBidirectional),
        "ServerBidirectional" => Ok(StreamType::ServerBidirectional),
        "ClientUnidirectional" => Ok(StreamType::ClientUnidirectional),
        "ServerUnidirectional" => Ok(StreamType::ServerUnidirectional),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid stream-type '{}'", value),
        )),
    }
}

fn stream_state_label(state: StreamState) -> &'static str {
    match state {
        StreamState::Open => "Open",
        StreamState::SendClosed => "SendClosed",
        StreamState::ReceivedClosed => "ReceivedClosed",
        StreamState::Closed => "Closed",
        StreamState::ResetSent => "ResetSent",
        StreamState::ResetReceived => "ResetReceived",
    }
}

fn parse_stream_state(value: &str) -> io::Result<StreamState> {
    match value {
        "Open" => Ok(StreamState::Open),
        "SendClosed" => Ok(StreamState::SendClosed),
        "ReceivedClosed" => Ok(StreamState::ReceivedClosed),
        "Closed" => Ok(StreamState::Closed),
        "ResetSent" => Ok(StreamState::ResetSent),
        "ResetReceived" => Ok(StreamState::ResetReceived),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid stream-state '{}'", value),
        )),
    }
}

fn serialize_stream(stream: &Stream) -> io::Result<Vec<u8>> {
    let send_buffer: Vec<u8> = stream.send_buffer.iter().copied().collect();
    let receive_buffer: Vec<u8> = stream.receive_buffer.iter().copied().collect();

    let mut out = format!(
        "id={}\nstream-type={}\nstate={}\nsend-offset={}\nsend-max-offset={}\nsend-final-offset={}\nreceive-offset={}\nreceive-max-offset={}\nreceive-final-offset={}\nfin-queued={}\nfin-sent={}\nfin-received={}\npriority={}\nerror-code={}\nsend-buffer={}\nreceive-buffer={}\nreceive-chunks-count={}\n",
        stream.id,
        stream_type_label(stream.stream_type),
        stream_state_label(stream.state),
        stream.send_offset,
        stream.send_max_offset,
        opt_u64_to_text(stream.send_final_offset),
        stream.receive_offset,
        stream.receive_max_offset,
        opt_u64_to_text(stream.receive_final_offset),
        stream.fin_queued,
        stream.fin_sent,
        stream.fin_received,
        stream.priority,
        opt_u64_to_text(stream.error_code),
        pem::encode(&send_buffer),
        pem::encode(&receive_buffer),
        stream.receive_chunks.len(),
    );

    for (i, (offset, chunk)) in stream.receive_chunks.iter().enumerate() {
        if *offset != chunk.offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream receive chunk key/offset mismatch",
            ));
        }

        out.push_str(&format!("chunk-{}-offset={}\n", i, chunk.offset));
        out.push_str(&format!("chunk-{}-data={}\n", i, pem::encode(&chunk.data)));
    }

    Ok(out.into_bytes())
}

fn deserialize_stream(raw_payload: &[u8]) -> io::Result<Stream> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure stream payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure stream payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let id = get_required_field(&map, "id")?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid stream id"))?;
    let stream_type = parse_stream_type(get_required_field(&map, "stream-type")?)?;
    let expected_type = StreamType::from_id(id);
    if stream_type != expected_type {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "stream-type mismatch for id {}: declared {:?}, expected {:?}",
                id, stream_type, expected_type
            ),
        ));
    }

    let state = parse_stream_state(get_required_field(&map, "state")?)?;
    let send_offset = get_required_field(&map, "send-offset")?.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid send-offset")
    })?;

    let send_max_offset = get_required_field(&map, "send-max-offset")?.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid send-max-offset")
    })?;

    let send_final_offset = parse_opt_u64(get_required_field(&map, "send-final-offset")?)?;
    let receive_offset = get_required_field(&map, "receive-offset")?.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid receive-offset")
    })?;

    let receive_max_offset = get_required_field(&map, "receive-max-offset")?.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid receive-max-offset")
    })?;

    let receive_final_offset = parse_opt_u64(get_required_field(&map, "receive-final-offset")?)?;
    let fin_queued = parse_bool(get_required_field(&map, "fin-queued")?)?;
    let fin_sent = parse_bool(get_required_field(&map, "fin-sent")?)?;
    let fin_received = parse_bool(get_required_field(&map, "fin-received")?)?;
    let priority = get_required_field(&map, "priority")?.parse::<u8>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid priority")
    })?;

    let error_code = parse_opt_u64(get_required_field(&map, "error-code")?)?;
    let send_buffer = pem::decode(get_required_field(&map, "send-buffer")?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid send-buffer encoding: {}", e),
        )
    })?;

    let receive_buffer = pem::decode(get_required_field(&map, "receive-buffer")?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid receive-buffer encoding: {}", e),
        )
    })?;

    let chunks_count = get_required_field(&map, "receive-chunks-count")?.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid receive-chunks-count")
    })?;

    let mut receive_chunks = BTreeMap::new();
    for i in 0..chunks_count {
        let offset_key = format!("chunk-{}-offset", i);
        let data_key = format!("chunk-{}-data", i);
        let chunk_offset = get_required_field(&map, &offset_key)?.parse::<u64>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid chunk offset")
        })?;

        let chunk_data = pem::decode(get_required_field(&map, &data_key)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk data encoding: {}", e),
            )
        })?;

        receive_chunks.insert(
            chunk_offset,
            DataChunk {
                offset: chunk_offset,
                data: chunk_data,
            },
        );
    }

    Ok(Stream {
        id,
        stream_type,
        state,
        send_buffer: send_buffer.into(),
        send_offset,
        send_max_offset,
        send_final_offset,
        receive_buffer: receive_buffer.into(),
        receive_offset,
        receive_max_offset,
        receive_final_offset,
        receive_chunks,
        fin_queued,
        fin_sent,
        fin_received,
        priority,
        error_code,
    })
}

fn get_required_field<'a>(map: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    map.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing '{}' in secure stream payload", key),
        )
    })
}

fn parse_bool(value: &str) -> io::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value '{}'", value),
        )),
    }
}

fn opt_u64_to_text(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
}

fn parse_opt_u64(value: &str) -> io::Result<Option<u64>> {
    if value.trim() == "-" {
        return Ok(None);
    }

    value.trim().parse::<u64>().map(Some).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid optional u64")
    })
}

fn compute_stream_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(STREAM_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(STREAM_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "stream secure blob missing header/body separator",
    ))
}

fn parse_secure_stream_meta(header: &str, body_len: usize) -> io::Result<SecureStreamBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != STREAM_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid stream secure blob magic",
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
                format!("invalid stream secure header line '{}'", line),
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
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in stream blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size in stream blob")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in stream blob")
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureStreamBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in stream secure blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in stream secure blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in stream secure blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in stream secure blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in stream secure blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in stream secure blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "stream encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
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
        assert_eq!(stream.readable(), 7);
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

    #[test]
    fn test_secure_stream_roundtrip_identity() {
        let mut stream = Stream::new(0, 2048, 2048);
        stream.write(b"abcdef").unwrap();
        stream.generate_frame(3).unwrap();
        stream.process_frame(10, vec![1, 2, 3], false).unwrap();
        stream.set_priority(220);

        let raw = serialize_stream(&stream).unwrap();
        let (meta, blob) = encode_secure_stream(&stream, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, decoded) = decode_secure_stream(&blob).unwrap();
        let decoded_raw = serialize_stream(&decoded).unwrap();
        assert_eq!(raw, decoded_raw);
    }

    #[test]
    fn test_secure_stream_roundtrip_compressed() {
        let mut stream = Stream::new(4, 4096, 4096);
        stream.write_fin(b"stream-payload").unwrap();
        stream.generate_frame(1024).unwrap().unwrap();
        stream.process_frame(0, b"rx-data".to_vec(), false).unwrap();
        stream.process_frame(7, b"-more".to_vec(), true).unwrap();

        let raw = serialize_stream(&stream).unwrap();
        let (_meta, blob) = encode_secure_stream(&stream, CompressionAlgorithm::Gzip).unwrap();
        let (_decoded_meta, decoded) = decode_secure_stream(&blob).unwrap();
        let decoded_raw = serialize_stream(&decoded).unwrap();

        assert_eq!(raw, decoded_raw);
    }

    #[test]
    fn test_secure_stream_tamper_detection() {
        let mut stream = Stream::new(0, 1024, 1024);
        stream.write(b"tamper-me").unwrap();

        let (_meta, blob) = encode_secure_stream(&stream, CompressionAlgorithm::Identity).unwrap();
        let mut tampered = blob.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x5A;
        }

        assert!(decode_secure_stream(&tampered).is_err());
    }
}