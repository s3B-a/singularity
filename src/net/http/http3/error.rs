use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP3_ERROR_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_ERROR_BLOB_V1";
const HTTP3_ERROR_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_ERROR_BLOB_BINDING_V1";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp3ErrorBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http3Error {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    ConnectError,
    VersionFallback,
    QpackDecompressionFailure,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
}

impl Http3Error {
    pub fn to_code(&self) -> u64 {
        match self {
            Http3Error::NoError => 0x100,
            Http3Error::GeneralProtocolError => 0x101,
            Http3Error::InternalError => 0x102,
            Http3Error::StreamCreationError => 0x103,
            Http3Error::ClosedCriticalStream => 0x104,
            Http3Error::FrameUnexpected => 0x105,
            Http3Error::FrameError => 0x106,
            Http3Error::ExcessiveLoad => 0x107,
            Http3Error::IdError => 0x108,
            Http3Error::SettingsError => 0x109,
            Http3Error::MissingSettings => 0x10a,
            Http3Error::RequestRejected => 0x10b,
            Http3Error::RequestCancelled => 0x10c,
            Http3Error::RequestIncomplete => 0x10d,
            Http3Error::MessageError => 0x10e,
            Http3Error::ConnectError => 0x10f,
            Http3Error::VersionFallback => 0x110,
            Http3Error::QpackDecompressionFailure => 0x200,
            Http3Error::QpackEncoderStreamError => 0x201,
            Http3Error::QpackDecoderStreamError => 0x202,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x100 => Some(Http3Error::NoError),
            0x101 => Some(Http3Error::GeneralProtocolError),
            0x102 => Some(Http3Error::InternalError),
            0x103 => Some(Http3Error::StreamCreationError),
            0x104 => Some(Http3Error::ClosedCriticalStream),
            0x105 => Some(Http3Error::FrameUnexpected),
            0x106 => Some(Http3Error::FrameError),
            0x107 => Some(Http3Error::ExcessiveLoad),
            0x108 => Some(Http3Error::IdError),
            0x109 => Some(Http3Error::SettingsError),
            0x10a => Some(Http3Error::MissingSettings),
            0x10b => Some(Http3Error::RequestRejected),
            0x10c => Some(Http3Error::RequestCancelled),
            0x10d => Some(Http3Error::RequestIncomplete),
            0x10e => Some(Http3Error::MessageError),
            0x10f => Some(Http3Error::ConnectError),
            0x110 => Some(Http3Error::VersionFallback),
            0x200 => Some(Http3Error::QpackDecompressionFailure),
            0x201 => Some(Http3Error::QpackEncoderStreamError),
            0x202 => Some(Http3Error::QpackDecoderStreamError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorCode {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError(u8),
}

impl ErrorCode {
    pub fn to_wire(&self) -> u64 {
        match self {
            ErrorCode::NoError => 0x00,
            ErrorCode::InternalError => 0x01,
            ErrorCode::ConnectionRefused => 0x02,
            ErrorCode::FlowControlError => 0x03,
            ErrorCode::StreamLimitError => 0x04,
            ErrorCode::StreamStateError => 0x05,
            ErrorCode::FinalSizeError => 0x06,
            ErrorCode::FrameEncodingError => 0x07,
            ErrorCode::TransportParameterError => 0x08,
            ErrorCode::ConnectionIdLimitError => 0x09,
            ErrorCode::ProtocolViolation => 0x0a,
            ErrorCode::InvalidToken => 0x0b,
            ErrorCode::ApplicationError => 0x0c,
            ErrorCode::CryptoBufferExceeded => 0x0d,
            ErrorCode::KeyUpdateError => 0x0e,
            ErrorCode::AeadLimitReached => 0x0f,
            ErrorCode::NoViablePath => 0x10,
            ErrorCode::CryptoError(alert) => 0x0100 + (*alert as u64),
        }
    }

    pub fn from_wire(code: u64) -> Self {
        match code {
            0x00 => ErrorCode::NoError,
            0x01 => ErrorCode::InternalError,
            0x02 => ErrorCode::ConnectionRefused,
            0x03 => ErrorCode::FlowControlError,
            0x04 => ErrorCode::StreamLimitError,
            0x05 => ErrorCode::StreamStateError,
            0x06 => ErrorCode::FinalSizeError,
            0x07 => ErrorCode::FrameEncodingError,
            0x08 => ErrorCode::TransportParameterError,
            0x09 => ErrorCode::ConnectionIdLimitError,
            0x0a => ErrorCode::ProtocolViolation,
            0x0b => ErrorCode::InvalidToken,
            0x0c => ErrorCode::ApplicationError,
            0x0d => ErrorCode::CryptoBufferExceeded,
            0x0e => ErrorCode::KeyUpdateError,
            0x0f => ErrorCode::AeadLimitReached,
            0x10 => ErrorCode::NoViablePath,
            0x0100..=0x01ff => ErrorCode::CryptoError((code - 0x0100) as u8),
            _ => ErrorCode::InternalError,
        }
    }

    pub fn is_crypto_error(&self) -> bool {
        matches!(self, ErrorCode::CryptoError(_))
    }

    pub fn tls_alert(&self) -> Option<u8> {
        match self {
            ErrorCode::CryptoError(alert) => Some(*alert),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Transport(ErrorCode, String),
    Http3(Http3Error, String),
    BufferTooShort,
    InvalidPacket,
    InvalidFrame,
    InvalidStreamState,
    StreamNotFound,
    ConnectionClosed,
    Timeout,
    Tls(String),
    Crypto(String),
    FlowControl(String),
    StreamLimit,
    Done,
    WouldBlock,
    InvalidOperation(String),
    Config(String),
    ProtocolViolation(String),
    VersionNegotiation,
    StatelessReset,
    KeyUnavailable,
    UnknownConnectionId,
    Qpack(String),
    CryptoError,
}

impl Error {
    pub fn transport(code: ErrorCode, msg: impl Into<String>) -> Self {
        Error::Transport(code, msg.into())
    }

    pub fn http3(code: Http3Error, msg: impl Into<String>) -> Self {
        Error::Http3(code, msg.into())
    }

    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn flow_control(msg: impl Into<String>) -> Self {
        Error::FlowControl(msg.into())
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ErrorBlobMeta, Vec<u8>)> {
        encode_secure_http3_error(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttp3ErrorBlobMeta, Vec<u8>)> {
        encode_secure_http3_error_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttp3ErrorBlobMeta, Self)> {
        decode_secure_http3_error(data)
    }

    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Error::Transport(_, _)
                | Error::ConnectionClosed
                | Error::Timeout
                | Error::Tls(_)
                | Error::ProtocolViolation(_)
                | Error::VersionNegotiation
                | Error::StatelessReset
        )
    }

    pub fn is_application_error(&self) -> bool {
        matches!(self, Error::Http3(_, _))
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(self, Error::WouldBlock | Error::Done)
    }
}

pub fn select_secure_http3_error_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http3_error(err: &Error, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ErrorBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http3_error(err);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate HTTP/3 error blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http3_error_blob_tag(
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
        magic = HTTP3_ERROR_BLOB_MAGIC,
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
        SecureHttp3ErrorBlobMeta {
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

pub fn encode_secure_http3_error_auto(err: &Error, accept_encoding: &str) -> io::Result<(SecureHttp3ErrorBlobMeta, Vec<u8>)> {
    let selected = select_secure_http3_error_algorithm(accept_encoding);
    encode_secure_http3_error(err, selected)
}

pub fn decode_secure_http3_error(data: &[u8]) -> io::Result<(SecureHttp3ErrorBlobMeta, Error)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http3_error_meta(&header, body.len())?;
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

    let expected_tag = compute_http3_error_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/3 error blob HMAC mismatch",
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
            "HTTP/3 error blob digest mismatch",
        ));
    }

    let err = deserialize_http3_error(&raw_payload)?;
    Ok((meta, err))
}

fn serialize_http3_error(err: &Error) -> Vec<u8> {
    let mut lines = Vec::new();
    match err {
        Error::Io(e) => {
            lines.push("variant=io".to_string());
            lines.push(format!("io-kind={}", io_error_kind_name(e.kind())));
            lines.push(format!("io-message={}", pem::encode(e.to_string().as_bytes())));
        }
        Error::Transport(code, msg) => {
            lines.push("variant=transport".to_string());
            lines.push(format!("transport-code={}", code.to_wire()));
            lines.push(format!("transport-message={}", pem::encode(msg.as_bytes())));
        }
        Error::Http3(code, msg) => {
            lines.push("variant=http3".to_string());
            lines.push(format!("http3-code={}", code.to_code()));
            lines.push(format!("http3-message={}", pem::encode(msg.as_bytes())));
        }
        Error::BufferTooShort => lines.push("variant=buffer-too-short".to_string()),
        Error::InvalidPacket => lines.push("variant=invalid-packet".to_string()),
        Error::InvalidFrame => lines.push("variant=invalid-frame".to_string()),
        Error::InvalidStreamState => lines.push("variant=invalid-stream-state".to_string()),
        Error::StreamNotFound => lines.push("variant=stream-not-found".to_string()),
        Error::ConnectionClosed => lines.push("variant=connection-closed".to_string()),
        Error::Timeout => lines.push("variant=timeout".to_string()),
        Error::Tls(msg) => {
            lines.push("variant=tls".to_string());
            lines.push(format!("tls-message={}", pem::encode(msg.as_bytes())));
        }
        Error::Crypto(msg) => {
            lines.push("variant=crypto".to_string());
            lines.push(format!("crypto-message={}", pem::encode(msg.as_bytes())));
        }
        Error::FlowControl(msg) => {
            lines.push("variant=flow-control".to_string());
            lines.push(format!("flow-control-message={}", pem::encode(msg.as_bytes())));
        }
        Error::StreamLimit => lines.push("variant=stream-limit".to_string()),
        Error::Done => lines.push("variant=done".to_string()),
        Error::WouldBlock => lines.push("variant=would-block".to_string()),
        Error::InvalidOperation(msg) => {
            lines.push("variant=invalid-operation".to_string());
            lines.push(format!(
                "invalid-operation-message={}",
                pem::encode(msg.as_bytes())
            ));
        }
        Error::Config(msg) => {
            lines.push("variant=config".to_string());
            lines.push(format!("config-message={}", pem::encode(msg.as_bytes())));
        }
        Error::ProtocolViolation(msg) => {
            lines.push("variant=protocol-violation".to_string());
            lines.push(format!(
                "protocol-violation-message={}",
                pem::encode(msg.as_bytes())
            ));
        }
        Error::VersionNegotiation => lines.push("variant=version-negotiation".to_string()),
        Error::StatelessReset => lines.push("variant=stateless-reset".to_string()),
        Error::KeyUnavailable => lines.push("variant=key-unavailable".to_string()),
        Error::UnknownConnectionId => lines.push("variant=unknown-connection-id".to_string()),
        Error::Qpack(msg) => {
            lines.push("variant=qpack".to_string());
            lines.push(format!("qpack-message={}", pem::encode(msg.as_bytes())));
        }
        Error::CryptoError => lines.push("variant=crypto-error".to_string()),
    }

    lines.join("\n").into_bytes()
}

fn deserialize_http3_error(raw_payload: &[u8]) -> io::Result<Error> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/3 error payload is not valid UTF-8",
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
                format!("invalid HTTP/3 error payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let variant = required_field(&kv, "variant")?;
    match variant {
        "io" => {
            let kind = parse_io_error_kind(required_field(&kv, "io-kind")?)?;
            let message = decode_string_field(required_field(&kv, "io-message")?, "io-message")?;
            Ok(Error::Io(io::Error::new(kind, message)))
        }
        "transport" => {
            let wire = parse_u64(required_field(&kv, "transport-code")?, "transport-code")?;
            let message = decode_string_field(
                required_field(&kv, "transport-message")?,
                "transport-message",
            )?;
            Ok(Error::Transport(ErrorCode::from_wire(wire), message))
        }
        "http3" => {
            let code = parse_u64(required_field(&kv, "http3-code")?, "http3-code")?;
            let message = decode_string_field(required_field(&kv, "http3-message")?, "http3-message")?;
            let parsed = Http3Error::from_code(code).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid http3-code {}", code),
                )
            })?;
            Ok(Error::Http3(parsed, message))
        }
        "buffer-too-short" => Ok(Error::BufferTooShort),
        "invalid-packet" => Ok(Error::InvalidPacket),
        "invalid-frame" => Ok(Error::InvalidFrame),
        "invalid-stream-state" => Ok(Error::InvalidStreamState),
        "stream-not-found" => Ok(Error::StreamNotFound),
        "connection-closed" => Ok(Error::ConnectionClosed),
        "timeout" => Ok(Error::Timeout),
        "tls" => Ok(Error::Tls(decode_string_field(
            required_field(&kv, "tls-message")?,
            "tls-message",
        )?)),
        "crypto" => Ok(Error::Crypto(decode_string_field(
            required_field(&kv, "crypto-message")?,
            "crypto-message",
        )?)),
        "flow-control" => Ok(Error::FlowControl(decode_string_field(
            required_field(&kv, "flow-control-message")?,
            "flow-control-message",
        )?)),
        "stream-limit" => Ok(Error::StreamLimit),
        "done" => Ok(Error::Done),
        "would-block" => Ok(Error::WouldBlock),
        "invalid-operation" => Ok(Error::InvalidOperation(decode_string_field(
            required_field(&kv, "invalid-operation-message")?,
            "invalid-operation-message",
        )?)),
        "config" => Ok(Error::Config(decode_string_field(
            required_field(&kv, "config-message")?,
            "config-message",
        )?)),
        "protocol-violation" => Ok(Error::ProtocolViolation(decode_string_field(
            required_field(&kv, "protocol-violation-message")?,
            "protocol-violation-message",
        )?)),
        "version-negotiation" => Ok(Error::VersionNegotiation),
        "stateless-reset" => Ok(Error::StatelessReset),
        "key-unavailable" => Ok(Error::KeyUnavailable),
        "unknown-connection-id" => Ok(Error::UnknownConnectionId),
        "qpack" => Ok(Error::Qpack(decode_string_field(
            required_field(&kv, "qpack-message")?,
            "qpack-message",
        )?)),
        "crypto-error" => Ok(Error::CryptoError),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown error variant '{}'", variant),
        )),
    }
}

fn io_error_kind_name(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "NotFound",
        io::ErrorKind::PermissionDenied => "PermissionDenied",
        io::ErrorKind::ConnectionRefused => "ConnectionRefused",
        io::ErrorKind::ConnectionReset => "ConnectionReset",
        io::ErrorKind::ConnectionAborted => "ConnectionAborted",
        io::ErrorKind::NotConnected => "NotConnected",
        io::ErrorKind::AddrInUse => "AddrInUse",
        io::ErrorKind::AddrNotAvailable => "AddrNotAvailable",
        io::ErrorKind::BrokenPipe => "BrokenPipe",
        io::ErrorKind::AlreadyExists => "AlreadyExists",
        io::ErrorKind::WouldBlock => "WouldBlock",
        io::ErrorKind::InvalidInput => "InvalidInput",
        io::ErrorKind::InvalidData => "InvalidData",
        io::ErrorKind::TimedOut => "TimedOut",
        io::ErrorKind::WriteZero => "WriteZero",
        io::ErrorKind::Interrupted => "Interrupted",
        io::ErrorKind::Unsupported => "Unsupported",
        io::ErrorKind::UnexpectedEof => "UnexpectedEof",
        io::ErrorKind::OutOfMemory => "OutOfMemory",
        _ => "Other",
    }
}

fn parse_io_error_kind(value: &str) -> io::Result<io::ErrorKind> {
    match value {
        "NotFound" => Ok(io::ErrorKind::NotFound),
        "PermissionDenied" => Ok(io::ErrorKind::PermissionDenied),
        "ConnectionRefused" => Ok(io::ErrorKind::ConnectionRefused),
        "ConnectionReset" => Ok(io::ErrorKind::ConnectionReset),
        "ConnectionAborted" => Ok(io::ErrorKind::ConnectionAborted),
        "NotConnected" => Ok(io::ErrorKind::NotConnected),
        "AddrInUse" => Ok(io::ErrorKind::AddrInUse),
        "AddrNotAvailable" => Ok(io::ErrorKind::AddrNotAvailable),
        "BrokenPipe" => Ok(io::ErrorKind::BrokenPipe),
        "AlreadyExists" => Ok(io::ErrorKind::AlreadyExists),
        "WouldBlock" => Ok(io::ErrorKind::WouldBlock),
        "InvalidInput" => Ok(io::ErrorKind::InvalidInput),
        "InvalidData" => Ok(io::ErrorKind::InvalidData),
        "TimedOut" => Ok(io::ErrorKind::TimedOut),
        "WriteZero" => Ok(io::ErrorKind::WriteZero),
        "Interrupted" => Ok(io::ErrorKind::Interrupted),
        "Unsupported" => Ok(io::ErrorKind::Unsupported),
        "UnexpectedEof" => Ok(io::ErrorKind::UnexpectedEof),
        "OutOfMemory" => Ok(io::ErrorKind::OutOfMemory),
        "Other" => Ok(io::ErrorKind::Other),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid io-kind '{}'", value),
        )),
    }
}

fn decode_string_field(value: &str, field: &str) -> io::Result<String> {
    let bytes = pem::decode(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", field),
        )
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in HTTP/3 error payload", key),
        )
    })
}

fn parse_u64(v: &str, field: &str) -> io::Result<u64> {
    v.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn compute_http3_error_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP3_ERROR_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP3_ERROR_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http3_error_meta(header: &str, body_len: usize) -> io::Result<SecureHttp3ErrorBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP3_ERROR_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure HTTP/3 error blob magic mismatch",
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
                format!("invalid secure HTTP/3 error header line '{}'", line),
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
            "missing nonce in secure HTTP/3 error blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure HTTP/3 error blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure HTTP/3 error blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure HTTP/3 error blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure HTTP/3 error blob",
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
            "missing issued-at in secure HTTP/3 error blob",
        )
    })?;

    Ok(SecureHttp3ErrorBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl fmt::Display for Http3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http3Error::NoError => write!(f, "No error"),
            Http3Error::GeneralProtocolError => write!(f, "General protocol error"),
            Http3Error::InternalError => write!(f, "Internal error"),
            Http3Error::StreamCreationError => write!(f, "Stream creation error"),
            Http3Error::ClosedCriticalStream => write!(f, "Closed critical stream"),
            Http3Error::FrameUnexpected => write!(f, "Frame unexpected"),
            Http3Error::FrameError => write!(f, "Frame error"),
            Http3Error::ExcessiveLoad => write!(f, "Excessive load"),
            Http3Error::IdError => write!(f, "ID error"),
            Http3Error::SettingsError => write!(f, "Settings error"),
            Http3Error::MissingSettings => write!(f, "Missing settings"),
            Http3Error::RequestRejected => write!(f, "Request rejected"),
            Http3Error::RequestCancelled => write!(f, "Request cancelled"),
            Http3Error::RequestIncomplete => write!(f, "Request incomplete"),
            Http3Error::MessageError => write!(f, "Message error"),
            Http3Error::ConnectError => write!(f, "Connect error"),
            Http3Error::VersionFallback => write!(f, "Version fallback"),
            Http3Error::QpackDecompressionFailure => write!(f, "QPACK decompression failed"),
            Http3Error::QpackEncoderStreamError => write!(f, "QPACK encoder stream error"),
            Http3Error::QpackDecoderStreamError => write!(f, "QPACK decoder stream error"),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::NoError => write!(f, "No error"),
            ErrorCode::InternalError => write!(f, "Internal error"),
            ErrorCode::ConnectionRefused => write!(f, "Connection refused"),
            ErrorCode::FlowControlError => write!(f, "Flow control error"),
            ErrorCode::StreamLimitError => write!(f, "Stream limit error"),
            ErrorCode::StreamStateError => write!(f, "Stream state error"),
            ErrorCode::FinalSizeError => write!(f, "Final size error"),
            ErrorCode::FrameEncodingError => write!(f, "Frame encoding error"),
            ErrorCode::TransportParameterError => write!(f, "Transport parameter error"),
            ErrorCode::ConnectionIdLimitError => write!(f, "Connection ID limit error"),
            ErrorCode::ProtocolViolation => write!(f, "Protocol violation"),
            ErrorCode::InvalidToken => write!(f, "Invalid token"),
            ErrorCode::ApplicationError => write!(f, "Application error"),
            ErrorCode::CryptoBufferExceeded => write!(f, "Crypto buffer exceeded"),
            ErrorCode::KeyUpdateError => write!(f, "Key update error"),
            ErrorCode::AeadLimitReached => write!(f, "AEAD limit reached"),
            ErrorCode::NoViablePath => write!(f, "No viable path"),
            ErrorCode::CryptoError(alert) => write!(f, "Crypto error (TLS alert: {})", alert),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Transport(code, msg) => write!(f, "Transport error {}: {}", code, msg),
            Error::Http3(code, msg) => write!(f, "HTTP/3 error {}: {}", code, msg),
            Error::BufferTooShort => write!(f, "Buffer too short"),
            Error::InvalidPacket => write!(f, "Invalid packet"),
            Error::InvalidFrame => write!(f, "Invalid frame"),
            Error::InvalidStreamState => write!(f, "Invalid stream state"),
            Error::StreamNotFound => write!(f, "Stream not found"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::Timeout => write!(f, "Connection timeout"),
            Error::Tls(msg) => write!(f, "TLS error: {}", msg),
            Error::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Error::FlowControl(msg) => write!(f, "Flow control error: {}", msg),
            Error::StreamLimit => write!(f, "Stream limit exceeded"),
            Error::Done => write!(f, "Done"),
            Error::WouldBlock => write!(f, "Would block"),
            Error::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            Error::Config(msg) => write!(f, "Configuration error: {}", msg),
            Error::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            Error::VersionNegotiation => write!(f, "Version negotiation failed"),
            Error::StatelessReset => write!(f, "Stateless reset"),
            Error::KeyUnavailable => write!(f, "Encryption key unavailable"),
            Error::UnknownConnectionId => write!(f, "Unknown connection ID"),
            Error::Qpack(msg) => write!(f, "QPACK error: {}", msg),
            Error::CryptoError => write!(f, "Cryptographic error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_error_codes() {
        assert_eq!(Http3Error::NoError.to_code(), 0x100);
        assert_eq!(Http3Error::GeneralProtocolError.to_code(), 0x101);
        assert_eq!(Http3Error::QpackDecompressionFailure.to_code(), 0x200);
    }

    #[test]
    fn test_http3_error_from_code() {
        assert_eq!(Http3Error::from_code(0x100), Some(Http3Error::NoError));
        assert_eq!(
            Http3Error::from_code(0x101),
            Some(Http3Error::GeneralProtocolError)
        );
        assert_eq!(Http3Error::from_code(0x999), None);
    }

    #[test]
    fn test_error_code_wire_format() {
        assert_eq!(ErrorCode::NoError.to_wire(), 0x00);
        assert_eq!(ErrorCode::InternalError.to_wire(), 0x01);
        assert_eq!(ErrorCode::CryptoError(42).to_wire(), 0x0100 + 42);
    }

    #[test]
    fn test_error_code_from_wire() {
        assert_eq!(ErrorCode::from_wire(0x00), ErrorCode::NoError);
        assert_eq!(ErrorCode::from_wire(0x01), ErrorCode::InternalError);
        assert_eq!(ErrorCode::from_wire(0x012a), ErrorCode::CryptoError(42));
    }

    #[test]
    fn test_crypto_error_detection() {
        assert!(ErrorCode::CryptoError(1).is_crypto_error());
        assert!(!ErrorCode::NoError.is_crypto_error());
        assert_eq!(ErrorCode::CryptoError(42).tls_alert(), Some(42));
        assert_eq!(ErrorCode::NoError.tls_alert(), None);
    }

    #[test]
    fn test_error_classification() {
        let err = Error::Transport(ErrorCode::InternalError, "test".to_string());
        assert!(err.is_connection_error());
        assert!(!err.is_application_error());
        assert!(!err.is_recoverable());

        let err = Error::Http3(Http3Error::FrameError, "test".to_string());
        assert!(!err.is_connection_error());
        assert!(err.is_application_error());

        let err = Error::WouldBlock;
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = Error::Transport(ErrorCode::FlowControlError, "overflow".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Flow control error"));
        assert!(display.contains("overflow"));
    }

    #[test]
    fn test_secure_http3_error_roundtrip() {
        let err = Error::Transport(ErrorCode::FlowControlError, "overflow".to_string());

        let (meta, blob) =
            encode_secure_http3_error(&err, CompressionAlgorithm::Identity).expect("encode blob");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded) = decode_secure_http3_error(&blob).expect("decode blob");
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);

        match decoded {
            Error::Transport(code, msg) => {
                assert_eq!(code, ErrorCode::FlowControlError);
                assert_eq!(msg, "overflow");
            }
            _ => panic!("decoded wrong error variant"),
        }
    }

    #[test]
    fn test_secure_http3_error_tamper_detection() {
        let err = Error::Qpack("table decode failed".to_string());
        let (_, mut blob) =
            encode_secure_http3_error(&err, CompressionAlgorithm::Identity).expect("encode blob");

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = decode_secure_http3_error(&blob);
        assert!(result.is_err());
    }
}