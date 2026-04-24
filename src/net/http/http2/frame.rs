use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const FRAME_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_FRAME_BLOB_V1";
const FRAME_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_FRAME_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureFrameBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x2 => Some(FrameType::Priority),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x5 => Some(FrameType::PushPromise),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::GoAway),
            0x8 => Some(FrameType::WindowUpdate),
            0x9 => Some(FrameType::Continuation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;

    pub fn new(flags: u8) -> Self {
        FrameFlags(flags)
    }

    pub fn empty() -> Self {
        FrameFlags(0)
    }

    pub fn has(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub stream_id: u32,
}

impl FrameHeader {
    pub const SIZE: usize = 9;
    pub const MAX_PAYLOAD_SIZE: u32 = 16777215; // 2^24 - 1

    pub fn new(frame_type: FrameType, flags: u8, stream_id: u32, length: u32) -> Self {
        Self {
            length,
            frame_type,
            flags: FrameFlags::new(flags),
            stream_id: stream_id & 0x7FFFFFFF,
        }
    }

    pub fn parse(bytes: &[u8; 9]) -> io::Result<Self> {
        let length = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        let frame_type = FrameType::from_u8(bytes[3]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unknown frame type")
        })?;

        let flags = FrameFlags::new(bytes[4]);
        let stream_id = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7FFFFFFF;

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    pub fn serialize(&self) -> [u8; 9] {
        let length_bytes = self.length.to_be_bytes();
        let stream_id_bytes = self.stream_id.to_be_bytes();

        [
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
            self.frame_type as u8,
            self.flags.value(),
            stream_id_bytes[0],
            stream_id_bytes[1],
            stream_id_bytes[2],
            stream_id_bytes[3],
        ]
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        let length = payload.len() as u32;
        Self {
            header: FrameHeader::new(frame_type, flags, stream_id, length),
            payload,
        }
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header_bytes = [0u8; 9];
        reader.read_exact(&mut header_bytes)?;
        let header = FrameHeader::parse(&header_bytes)?;

        if header.length > FrameHeader::MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame payload too large",
            ));
        }

        let mut payload = vec![0u8; header.length as usize];
        reader.read_exact(&mut payload)?;

        Ok(Self { header, payload })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.header.serialize())?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn data(stream_id: u32, data: Vec<u8>, end_stream: bool) -> Self {
        let flags = if end_stream { FrameFlags::END_STREAM } else { 0 };
        Self::new(FrameType::Data, flags, stream_id, data)
    }

    pub fn headers(stream_id: u32, headers: Vec<u8>, end_headers: bool, end_stream: bool) -> Self {
        let mut flags = 0;
        if end_headers {
            flags |= FrameFlags::END_HEADERS;
        }
        if end_stream {
            flags |= FrameFlags::END_STREAM;
        }

        Self::new(FrameType::Headers, flags, stream_id, headers)
    }

    pub fn priority(stream_id: u32, exclusive: bool, dependency: u32, weight: u8) -> Self {
        let dep = if exclusive {
            dependency | 0x80000000
        } else {
            dependency
        };

        let mut payload = dep.to_be_bytes().to_vec();
        payload.push(weight);

        Self::new(FrameType::Priority, 0, stream_id, payload)
    }

    pub fn rst_stream(stream_id: u32, error_code: u32) -> Self {
        Self::new(
            FrameType::RstStream,
            0,
            stream_id,
            error_code.to_be_bytes().to_vec(),
        )
    }

    pub fn settings(settings: Vec<(u16, u32)>) -> Self {
        let mut payload = Vec::new();
        for (id, value) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }

        Self::new(FrameType::Settings, 0, 0, payload)
    }

    pub fn settings_ack() -> Self {
        Self::new(FrameType::Settings, FrameFlags::ACK, 0, Vec::new())
    }

    pub fn push_promise(stream_id: u32, promised_stream_id: u32, headers: Vec<u8>, end_headers: bool) -> Self {
        let flags = if end_headers { FrameFlags::END_HEADERS } else { 0 };
        let mut payload = promised_stream_id.to_be_bytes().to_vec();
        payload.extend(headers);
        Self::new(FrameType::PushPromise, flags, stream_id, payload)
    }

    pub fn ping(data: [u8; 8], ack: bool) -> Self {
        let flags = if ack { FrameFlags::ACK } else { 0 };
        Self::new(FrameType::Ping, flags, 0, data.to_vec())
    }

    pub fn goaway(last_stream_id: u32, error_code: u32, debug_data: Vec<u8>) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&last_stream_id.to_be_bytes());
        payload.extend_from_slice(&error_code.to_be_bytes());
        payload.extend_from_slice(&debug_data);
        Self::new(FrameType::GoAway, 0, 0, payload)
    }

    pub fn window_update(stream_id: u32, increment: u32) -> Self {
        let payload = (increment & 0x7FFFFFFF).to_be_bytes().to_vec();
        Self::new(FrameType::WindowUpdate, 0, stream_id, payload)
    }

    pub fn continuation(stream_id: u32, headers: Vec<u8>, end_headers: bool) -> Self {
        let flags = if end_headers { FrameFlags::END_HEADERS } else { 0 };
        Self::new(FrameType::Continuation, flags, stream_id, headers)
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
        encode_secure_frame(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
        encode_secure_frame_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureFrameBlobMeta, Self)> {
        decode_secure_frame(data)
    }
}

pub fn select_secure_frame_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_frame(frame: &Frame, algorithm: CompressionAlgorithm) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_frame(frame)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate frame blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_frame_blob_tag(
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
        magic = FRAME_BLOB_MAGIC,
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
        SecureFrameBlobMeta {
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

pub fn encode_secure_frame_auto(frame: &Frame, accept_encoding: &str) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
    let selected = select_secure_frame_algorithm(accept_encoding);
    encode_secure_frame(frame, selected)
}

pub fn decode_secure_frame(data: &[u8]) -> io::Result<(SecureFrameBlobMeta, Frame)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_frame_meta(&header, body.len())?;
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

    let expected_tag = compute_frame_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame blob HMAC mismatch",
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
            "frame blob digest mismatch",
        ));
    }

    let frame = deserialize_frame(&raw_payload)?;
    Ok((meta, frame))
}

fn serialize_frame(frame: &Frame) -> io::Result<Vec<u8>> {
    if frame.payload.len() > FrameHeader::MAX_PAYLOAD_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload too large",
        ));
    }

    let normalized_header = FrameHeader::new(
        frame.header.frame_type,
        frame.header.flags.value(),
        frame.header.stream_id,
        frame.payload.len() as u32,
    );

    let mut out = Vec::with_capacity(FrameHeader::SIZE + frame.payload.len());
    out.extend_from_slice(&normalized_header.serialize());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

fn deserialize_frame(raw_payload: &[u8]) -> io::Result<Frame> {
    if raw_payload.len() < FrameHeader::SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "serialized frame is too short",
        ));
    }

    let mut header_bytes = [0u8; 9];
    header_bytes.copy_from_slice(&raw_payload[..FrameHeader::SIZE]);
    let header = FrameHeader::parse(&header_bytes)?;
    let payload = raw_payload[FrameHeader::SIZE..].to_vec();
    if payload.len() != header.length as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame length mismatch: header {}, payload {}",
                header.length,
                payload.len()
            ),
        ));
    }

    Ok(Frame { header, payload })
}

fn compute_frame_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(FRAME_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(FRAME_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_frame_meta(header: &str, body_len: usize) -> io::Result<SecureFrameBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != FRAME_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure frame blob magic mismatch",
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
                format!("invalid secure frame header line '{}'", line),
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
            "missing nonce in secure frame blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure frame blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure frame blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure frame blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure frame blob",
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
            "missing issued-at in secure frame blob",
        )
    })?;

    Ok(SecureFrameBlobMeta {
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
    use std::io::Cursor;

    #[test]
    fn test_frame_read_write_roundtrip() {
        let original = Frame::headers(1, b":method: GET".to_vec(), true, false);
        let mut wire = Vec::new();
        original.write(&mut wire).unwrap();

        let mut cursor = Cursor::new(wire);
        let parsed = Frame::read(&mut cursor).unwrap();

        assert_eq!(parsed.header.frame_type, FrameType::Headers);
        assert_eq!(parsed.header.stream_id, 1);
        assert_eq!(parsed.header.flags.value(), original.header.flags.value());
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_secure_frame_roundtrip_identity() {
        let frame = Frame::data(3, b"hello-http2".to_vec(), true);

        let (_meta, blob) = encode_secure_frame(&frame, CompressionAlgorithm::Identity).unwrap();
        let (_decoded_meta, decoded) = decode_secure_frame(&blob).unwrap();

        assert_eq!(decoded.header.frame_type, frame.header.frame_type);
        assert_eq!(decoded.header.stream_id, frame.header.stream_id);
        assert_eq!(decoded.header.flags.value(), frame.header.flags.value());
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn test_secure_frame_roundtrip_compressed() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let frame = Frame::data(5, payload, false);

        let (_meta, blob) = encode_secure_frame(&frame, CompressionAlgorithm::Gzip).unwrap();
        let (_decoded_meta, decoded) = decode_secure_frame(&blob).unwrap();

        assert_eq!(decoded.header.frame_type, FrameType::Data);
        assert_eq!(decoded.header.stream_id, 5);
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn test_secure_frame_tamper_detected() {
        let frame = Frame::ping(*b"12345678", false);
        let (_meta, mut blob) = encode_secure_frame(&frame, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_frame(&blob).is_err());
    }
}