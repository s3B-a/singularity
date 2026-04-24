pub mod alpn;
mod connection;
mod error;
mod flow_control;
mod frame;
pub mod hpack;
mod priority;
mod push;
mod settings;
mod stream;
mod scheduler;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub use alpn::{AlpnNegotiator, AlpnProtocol, NpnNegotiator, NpnProtocol};
pub use connection::Http2Connection;
pub use error::{ErrorCode, Http2Error, Result};
pub use flow_control::FlowControl;
pub use frame::{Frame, FrameFlags, FrameHeader, FrameType};
pub use hpack::HpackCodec;
pub use priority::{Priority, PriorityTree};
pub use push::{PushManager, PushConfig, PushedResource, PushStatus, PushStats};
pub use settings::{Settings, SettingId};
pub use scheduler::{PriorityScheduler, DependencyTreeStats, StreamScheduleState};
pub use stream::{Http2Stream, StreamState};

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// RFC 7540 standards
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;
pub const MAX_FRAME_SIZE: u32 = 16777215;
pub const MIN_FRAME_SIZE: u32 = 16384;

const HTTP2_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_BLOB_V1";
const HTTP2_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp2BlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub fn select_secure_http2_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http2_payload(payload: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp2BlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = payload.to_vec();
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate http2 blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http2_blob_tag(
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
        magic = HTTP2_BLOB_MAGIC,
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
        SecureHttp2BlobMeta {
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

pub fn encode_secure_http2_payload_auto(payload: &[u8], accept_encoding: &str) -> io::Result<(SecureHttp2BlobMeta, Vec<u8>)> {
    let selected = select_secure_http2_algorithm(accept_encoding);
    encode_secure_http2_payload(payload, selected)
}

pub fn decode_secure_http2_payload(data: &[u8]) -> io::Result<(SecureHttp2BlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http2_meta(&header, body.len())?;
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

    let expected_tag = compute_http2_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http2 blob HMAC mismatch",
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
            "http2 blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

fn compute_http2_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP2_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP2_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http2_meta(header: &str, body_len: usize) -> io::Result<SecureHttp2BlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP2_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http2 blob magic mismatch",
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
                format!("invalid secure http2 header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", value.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                digest_b64 = Some(
                    value.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                    })?.to_string(),
                );
            }
            "tag" => {
                tag_b64 = Some(
                    value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                    })?.to_string(),
                );
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
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure http2 blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure http2 blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure http2 blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure http2 blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing encoded-size in secure http2 blob")
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
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in secure http2 blob")
    })?;

    Ok(SecureHttp2BlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}