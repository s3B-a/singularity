use super::error::{ErrorCode, Http2Error, Result};
use super::flow_control::FlowControl;
use super::priority::Priority;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP2_STREAM_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_STREAM_BLOB_V1";
const HTTP2_STREAM_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_STREAM_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp2StreamBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

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
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
    }

    pub fn is_readable(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
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
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
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
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
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

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2StreamBlobMeta, Vec<u8>)> {
        encode_secure_http2_stream(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttp2StreamBlobMeta, Vec<u8>)> {
        encode_secure_http2_stream_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttp2StreamBlobMeta, Self)> {
        decode_secure_http2_stream(data)
    }
}

pub fn select_secure_http2_stream_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http2_stream(stream: &Http2Stream, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2StreamBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http2_stream(stream)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate HTTP/2 stream blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http2_stream_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = HTTP2_STREAM_BLOB_MAGIC,
        encoding = selected_algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
        issued_at = issued_at_unix,
    );

    let mut blob = header.into_bytes();
    blob.extend_from_slice(&encoded_payload);

    Ok((
        SecureHttp2StreamBlobMeta {
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

pub fn encode_secure_http2_stream_auto(stream: &Http2Stream, accept_encoding: &str) -> io::Result<(SecureHttp2StreamBlobMeta, Vec<u8>)> {
    let selected = select_secure_http2_stream_algorithm(accept_encoding);
    encode_secure_http2_stream(stream, selected)
}

pub fn decode_secure_http2_stream(data: &[u8]) -> io::Result<(SecureHttp2StreamBlobMeta, Http2Stream)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http2_stream_meta(&header, body.len())?;
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

    let expected_tag = compute_http2_stream_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 stream blob HMAC mismatch",
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
            "HTTP/2 stream blob digest mismatch",
        ));
    }

    let stream = deserialize_http2_stream(&raw_payload)?;
    Ok((meta, stream))
}

fn serialize_http2_stream(stream: &Http2Stream) -> io::Result<Vec<u8>> {
    let mut lines = Vec::new();
    lines.push(format!("id={}", stream.id));
    lines.push(format!("state={}", stream_state_as_str(stream.state)));
    lines.push(format!(
        "priority-stream-dependency={}",
        stream.priority.stream_dependency
    ));

    lines.push(format!("priority-weight={}", stream.priority.weight));
    lines.push(format!("priority-exclusive={}", stream.priority.exclusive));
    lines.push(format!("headers-received={}", stream.headers_received));
    lines.push(format!("headers-sent={}", stream.headers_sent));
    lines.push(format!("end-stream-received={}", stream.end_stream_received));
    lines.push(format!("end-stream-sent={}", stream.end_stream_sent));

    let (_flow_meta, flow_blob) = stream.flow_control.to_secure_blob(CompressionAlgorithm::Identity)?;
    lines.push(format!("flow-control-blob={}", pem::encode(&flow_blob)));
    append_header_pairs(&mut lines, "request-header", &stream.request_headers);
    append_header_pairs(&mut lines, "response-header", &stream.response_headers);
    append_header_pairs(&mut lines, "trailer", &stream.trailers);
    lines.push(format!("send-buffer-count={}", stream.send_buffer.len()));
    for (idx, chunk) in stream.send_buffer.iter().enumerate() {
        lines.push(format!("send-buffer-{}={}", idx, pem::encode(chunk)));
    }

    lines.push(format!("recv-buffer={}", pem::encode(&stream.recv_buffer)));

    Ok(lines.join("\n").into_bytes())
}

fn deserialize_http2_stream(raw_payload: &[u8]) -> io::Result<Http2Stream> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 stream payload is not valid UTF-8",
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
                format!("invalid stream payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.trim().to_string(), value.to_string());
    }

    let id = parse_u32(required_field(&kv, "id")?, "id")?;
    let state = parse_stream_state(required_field(&kv, "state")?)?;
    let priority_stream_dependency = parse_u32(
        required_field(&kv, "priority-stream-dependency")?,
        "priority-stream-dependency",
    )?;

    let priority_weight = parse_u8(required_field(&kv, "priority-weight")?, "priority-weight")?;
    let priority_exclusive = parse_bool(required_field(&kv, "priority-exclusive")?)?;
    let headers_received = parse_bool(required_field(&kv, "headers-received")?)?;
    let headers_sent = parse_bool(required_field(&kv, "headers-sent")?)?;
    let end_stream_received = parse_bool(required_field(&kv, "end-stream-received")?)?;
    let end_stream_sent = parse_bool(required_field(&kv, "end-stream-sent")?)?;
    let flow_blob_b64 = required_field(&kv, "flow-control-blob")?;
    let flow_blob = pem::decode(flow_blob_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid flow-control-blob encoding: {}", e),
        )
    })?;

    let (_flow_meta, flow_control) = FlowControl::from_secure_blob(&flow_blob)?;
    let request_headers = parse_header_pairs(&kv, "request-header")?;
    let response_headers = parse_header_pairs(&kv, "response-header")?;
    let trailers = parse_header_pairs(&kv, "trailer")?;
    let send_buffer_count = parse_usize(required_field(&kv, "send-buffer-count")?, "send-buffer-count")?;
    let mut send_buffer = VecDeque::with_capacity(send_buffer_count);
    for idx in 0..send_buffer_count {
        let key = format!("send-buffer-{}", idx);
        let chunk_b64 = required_field(&kv, &key)?;
        let chunk = pem::decode(chunk_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} encoding: {}", key, e),
            )
        })?;

        send_buffer.push_back(chunk);
    }

    let recv_buffer = pem::decode(required_field(&kv, "recv-buffer")?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid recv-buffer encoding: {}", e),
        )
    })?;

    Ok(Http2Stream {
        id,
        state,
        flow_control,
        priority: Priority::new(priority_stream_dependency, priority_weight, priority_exclusive),
        send_buffer,
        recv_buffer,
        request_headers,
        response_headers,
        trailers,
        headers_received,
        headers_sent,
        end_stream_received,
        end_stream_sent,
    })
}

fn append_header_pairs(lines: &mut Vec<String>, prefix: &str, pairs: &[(String, String)]) {
    lines.push(format!("{}-count={}", prefix, pairs.len()));
    for (idx, (name, value)) in pairs.iter().enumerate() {
        lines.push(format!(
            "{}-{}-name={}",
            prefix,
            idx,
            pem::encode(name.as_bytes())
        ));

        lines.push(format!(
            "{}-{}-value={}",
            prefix,
            idx,
            pem::encode(value.as_bytes())
        ));
    }
}

fn parse_header_pairs(kv: &HashMap<String, String>, prefix: &str) -> io::Result<Vec<(String, String)>> {
    let count_key = format!("{}-count", prefix);
    let count = parse_usize(required_field(kv, &count_key)?, &count_key)?;
    let mut pairs = Vec::with_capacity(count);
    for idx in 0..count {
        let name_key = format!("{}-{}-name", prefix, idx);
        let value_key = format!("{}-{}-value", prefix, idx);
        let name = pem::decode(required_field(kv, &name_key)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} encoding: {}", name_key, e),
            )
        })?;

        let value = pem::decode(required_field(kv, &value_key)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} encoding: {}", value_key, e),
            )
        })?;

        let name = String::from_utf8(name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not valid UTF-8", name_key),
            )
        })?;

        let value = String::from_utf8(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not valid UTF-8", value_key),
            )
        })?;

        pairs.push((name, value));
    }

    Ok(pairs)
}

fn stream_state_as_str(state: StreamState) -> &'static str {
    match state {
        StreamState::Idle => "idle",
        StreamState::ReservedLocal => "reserved-local",
        StreamState::ReservedRemote => "reserved-remote",
        StreamState::Open => "open",
        StreamState::HalfClosedLocal => "half-closed-local",
        StreamState::HalfClosedRemote => "half-closed-remote",
        StreamState::Closed => "closed",
    }
}

fn parse_stream_state(v: &str) -> io::Result<StreamState> {
    match v {
        "idle" => Ok(StreamState::Idle),
        "reserved-local" => Ok(StreamState::ReservedLocal),
        "reserved-remote" => Ok(StreamState::ReservedRemote),
        "open" => Ok(StreamState::Open),
        "half-closed-local" => Ok(StreamState::HalfClosedLocal),
        "half-closed-remote" => Ok(StreamState::HalfClosedRemote),
        "closed" => Ok(StreamState::Closed),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid stream state '{}'", v),
        )),
    }
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in stream payload", key),
        )
    })
}

fn parse_u32(v: &str, field: &str) -> io::Result<u32> {
    v.parse::<u32>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_u8(v: &str, field: &str) -> io::Result<u8> {
    v.parse::<u8>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid bool '{}'", v),
        )),
    }
}

fn compute_http2_stream_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP2_STREAM_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP2_STREAM_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http2_stream_meta(header: &str, body_len: usize) -> io::Result<SecureHttp2StreamBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP2_STREAM_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure HTTP/2 stream blob magic mismatch",
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
                format!("invalid secure stream header line '{}'", line),
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
            "missing nonce in secure stream blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure stream blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure stream blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure stream blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure stream blob",
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
            "missing issued-at in secure stream blob",
        )
    })?;

    Ok(SecureHttp2StreamBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_stream_data_queue_and_chunk() {
        let mut stream = Http2Stream::new(1, 65_535);
        stream.send_headers().unwrap();
        stream.queue_data(b"hello".to_vec()).unwrap();

        let chunk = stream.next_data_chunk(3).unwrap();
        assert_eq!(chunk, b"hel".to_vec());
        assert!(stream.has_pending_data());
    }

    #[test]
    fn test_secure_http2_stream_roundtrip_identity() {
        let mut stream = Http2Stream::new(3, 65_535);
        stream.send_headers().unwrap();
        stream.set_priority(Priority::new(0, 32, false));
        stream.set_request_headers(vec![(":method".to_string(), "GET".to_string())]);
        stream.add_response_headers(vec![(":status".to_string(), "200".to_string())]);
        stream.add_trailers(vec![("x-end".to_string(), "1".to_string())]);
        stream.queue_data(vec![1, 2, 3]).unwrap();
        stream.receive_data(vec![9, 8, 7]).unwrap();
        stream.send_end_stream().unwrap();

        let (_meta, blob) =
            encode_secure_http2_stream(&stream, CompressionAlgorithm::Identity).unwrap();
        let (_decoded_meta, decoded) = decode_secure_http2_stream(&blob).unwrap();

        assert_eq!(decoded.id(), stream.id());
        assert_eq!(decoded.state(), stream.state());
        assert_eq!(decoded.request_headers(), stream.request_headers());
        assert_eq!(decoded.response_headers(), stream.response_headers());
        assert_eq!(decoded.trailers(), stream.trailers());
        assert_eq!(decoded.send_buffer, stream.send_buffer);
        assert_eq!(decoded.data(), stream.data());
        assert_eq!(
            decoded.flow_control().initial_window_size(),
            stream.flow_control().initial_window_size()
        );
    }

    #[test]
    fn test_secure_http2_stream_tamper_detected() {
        let mut stream = Http2Stream::new(5, 65_535);
        stream.send_headers().unwrap();
        stream.queue_data(b"abc".to_vec()).unwrap();

        let (_meta, mut blob) =
            encode_secure_http2_stream(&stream, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_http2_stream(&blob).is_err());
    }
}