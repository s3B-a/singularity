use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP2_ERROR_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_ERROR_BLOB_V1";
const HTTP2_ERROR_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_ERROR_BLOB_BINDING_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl ErrorCode {
    pub fn from_u32(code: u32) -> Self {
        match code {
            0x0 => ErrorCode::NoError,
            0x1 => ErrorCode::ProtocolError,
            0x2 => ErrorCode::InternalError,
            0x3 => ErrorCode::FlowControlError,
            0x4 => ErrorCode::SettingsTimeout,
            0x5 => ErrorCode::StreamClosed,
            0x6 => ErrorCode::FrameSizeError,
            0x7 => ErrorCode::RefusedStream,
            0x8 => ErrorCode::Cancel,
            0x9 => ErrorCode::CompressionError,
            0xa => ErrorCode::ConnectError,
            0xb => ErrorCode::EnhanceYourCalm,
            0xc => ErrorCode::InadequateSecurity,
            0xd => ErrorCode::Http11Required,
            _ => ErrorCode::InternalError,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::NoError => "NO_ERROR",
            ErrorCode::ProtocolError => "PROTOCOL_ERROR",
            ErrorCode::InternalError => "INTERNAL_ERROR",
            ErrorCode::FlowControlError => "FLOW_CONTROL_ERROR",
            ErrorCode::SettingsTimeout => "SETTINGS_TIMEOUT",
            ErrorCode::StreamClosed => "STREAM_CLOSED",
            ErrorCode::FrameSizeError => "FRAME_SIZE_ERROR",
            ErrorCode::RefusedStream => "REFUSED_STREAM",
            ErrorCode::Cancel => "CANCEL",
            ErrorCode::CompressionError => "COMPRESSION_ERROR",
            ErrorCode::ConnectError => "CONNECT_ERROR",
            ErrorCode::EnhanceYourCalm => "ENHANCE_YOUR_CALM",
            ErrorCode::InadequateSecurity => "INADEQUATE_SECURITY",
            ErrorCode::Http11Required => "HTTP_1_1_REQUIRED",
        }
    }
}

#[derive(Debug)]
pub enum Http2Error {
    Protocol(ErrorCode, String),
    Io(io::Error),
    ConnectionClosed,
    StreamNotFound(u32),
    InvalidStreamId(u32),
    InvalidFrameSize,
    CompressionFailed,
    DecompressionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp2ErrorBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

impl fmt::Display for Http2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http2Error::Protocol(code, msg) => write!(f, "{}: {}", code.as_str(), msg),
            Http2Error::Io(e) => write!(f, "IO error: {}", e),
            Http2Error::ConnectionClosed => write!(f, "Connection closed"),
            Http2Error::StreamNotFound(id) => write!(f, "Stream {} not found", id),
            Http2Error::InvalidStreamId(id) => write!(f, "Invalid stream ID: {}", id),
            Http2Error::InvalidFrameSize => write!(f, "Invalid frame size"),
            Http2Error::CompressionFailed => write!(f, "Header compression failed"),
            Http2Error::DecompressionFailed => write!(f, "Header decompression failed"),
        }
    }
}

impl std::error::Error for Http2Error {}

impl From<io::Error> for Http2Error {
    fn from(err: io::Error) -> Self {
        Http2Error::Io(err)
    }
}

pub fn select_secure_http2_error_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http2_error(err: &Http2Error, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2ErrorBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http2_error(err);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate HTTP/2 error blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http2_error_blob_tag(
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
        magic = HTTP2_ERROR_BLOB_MAGIC,
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
        SecureHttp2ErrorBlobMeta {
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

pub fn encode_secure_http2_error_auto(err: &Http2Error, accept_encoding: &str) -> io::Result<(SecureHttp2ErrorBlobMeta, Vec<u8>)> {
    let selected = select_secure_http2_error_algorithm(accept_encoding);
    encode_secure_http2_error(err, selected)
}

pub fn decode_secure_http2_error(data: &[u8]) -> io::Result<(SecureHttp2ErrorBlobMeta, Http2Error)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http2_error_meta(&header, body.len())?;
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

    let expected_tag = compute_http2_error_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 error blob HMAC mismatch",
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
            "HTTP/2 error blob digest mismatch",
        ));
    }

    let err = deserialize_http2_error(&raw_payload)?;
    Ok((meta, err))
}

fn serialize_http2_error(err: &Http2Error) -> Vec<u8> {
    let mut lines = Vec::new();
    match err {
        Http2Error::Protocol(code, msg) => {
            lines.push("kind=protocol".to_string());
            lines.push(format!("code={}", *code as u32));
            lines.push(format!("msg={}", pem::encode(msg.as_bytes())));
        }
        Http2Error::Io(e) => {
            lines.push("kind=io".to_string());
            lines.push(format!("msg={}", pem::encode(e.to_string().as_bytes())));
        }
        Http2Error::ConnectionClosed => {
            lines.push("kind=connection-closed".to_string());
        }
        Http2Error::StreamNotFound(id) => {
            lines.push("kind=stream-not-found".to_string());
            lines.push(format!("stream-id={}", id));
        }
        Http2Error::InvalidStreamId(id) => {
            lines.push("kind=invalid-stream-id".to_string());
            lines.push(format!("stream-id={}", id));
        }
        Http2Error::InvalidFrameSize => {
            lines.push("kind=invalid-frame-size".to_string());
        }
        Http2Error::CompressionFailed => {
            lines.push("kind=compression-failed".to_string());
        }
        Http2Error::DecompressionFailed => {
            lines.push("kind=decompression-failed".to_string());
        }
    }

    lines.join("\n").into_bytes()
}

fn deserialize_http2_error(raw_payload: &[u8]) -> io::Result<Http2Error> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 error payload is not valid UTF-8",
        )
    })?;

    let mut kind: Option<String> = None;
    let mut code: Option<u32> = None;
    let mut msg: Option<String> = None;
    let mut stream_id: Option<u32> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid error payload line '{}'", trimmed),
            )
        })?;

        match key.trim() {
            "kind" => kind = Some(value.trim().to_string()),
            "code" => code = Some(parse_u32(value.trim(), "code")?),
            "msg" => {
                let decoded = pem::decode(value.trim()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid msg encoding: {}", e),
                    )
                })?;
                let message = String::from_utf8(decoded).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "msg is not valid UTF-8")
                })?;
                msg = Some(message);
            }
            "stream-id" => stream_id = Some(parse_u32(value.trim(), "stream-id")?),
            _ => {}
        }
    }

    let kind = kind.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing kind in error payload")
    })?;

    match kind.as_str() {
        "protocol" => {
            let parsed_code = code.unwrap_or(ErrorCode::InternalError as u32);
            let parsed_msg = msg.unwrap_or_else(|| "protocol error".to_string());
            Ok(Http2Error::Protocol(
                ErrorCode::from_u32(parsed_code),
                parsed_msg,
            ))
        }
        "io" => {
            let parsed_msg = msg.unwrap_or_else(|| "io error".to_string());
            Ok(Http2Error::Io(io::Error::new(io::ErrorKind::Other, parsed_msg)))
        }
        "connection-closed" => Ok(Http2Error::ConnectionClosed),
        "stream-not-found" => Ok(Http2Error::StreamNotFound(stream_id.unwrap_or(0))),
        "invalid-stream-id" => Ok(Http2Error::InvalidStreamId(stream_id.unwrap_or(0))),
        "invalid-frame-size" => Ok(Http2Error::InvalidFrameSize),
        "compression-failed" => Ok(Http2Error::CompressionFailed),
        "decompression-failed" => Ok(Http2Error::DecompressionFailed),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported error kind '{}'", other),
        )),
    }
}

fn parse_u32(v: &str, field: &str) -> io::Result<u32> {
    v.parse::<u32>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn compute_http2_error_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP2_ERROR_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP2_ERROR_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http2_error_meta(header: &str, body_len: usize) -> io::Result<SecureHttp2ErrorBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP2_ERROR_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure HTTP/2 error blob magic mismatch",
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
                format!("invalid secure error header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    },
                )?;
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
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure error blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure error blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure error blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure error blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure error blob",
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
            "missing issued-at in secure error blob",
        )
    })?;

    Ok(SecureHttp2ErrorBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

pub type Result<T> = std::result::Result<T, Http2Error>;