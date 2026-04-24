use super::error::{ErrorCode, Http2Error, Result};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const FLOW_CONTROL_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_FLOW_CONTROL_BLOB_V1";
const FLOW_CONTROL_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_FLOW_CONTROL_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureFlowControlBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct FlowControl {
    window_size: i32,
    initial_window_size: u32,
}

impl FlowControl {
    pub fn new(initial_window_size: u32) -> Self {
        Self {
            window_size: initial_window_size as i32,
            initial_window_size,
        }
    }

    pub fn window_size(&self) -> i32 {
        self.window_size
    }

    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    pub fn can_send(&self, size: usize) -> bool {
        self.window_size >= size as i32
    }

    pub fn consume(&mut self, size: usize) -> Result<()> {
        if !self.can_send(size) {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window exceeded".to_string()
            ));
        }

        self.window_size -= size as i32;
        Ok(())
    }

    pub fn increase(&mut self, increment: u32) -> Result<()> {
        if increment == 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Window update increment must be positive".to_string(),
            ));
        }

        let new_size = self.window_size as i64 + increment as i64;
        if new_size > i32::MAX as i64 {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window overflow".to_string(),
            ));
        }

        self.window_size = new_size as i32;
        Ok(())
    }

    pub fn restore(&mut self, size: usize) {
        self.window_size += size as i32;
    }

    pub fn update_initial_window_size(&mut self, new_size: u32) -> Result<()> {
        let diff = new_size as i64 - self.initial_window_size as i64;
        let new_window = self.window_size as i64 + diff;
        if new_window > i32::MAX as i64 || new_window < i32::MIN as i64 {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window overflow".to_string(),
            ));
        }

        self.window_size = new_window as i32;
        self.initial_window_size = new_size;
        Ok(())
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureFlowControlBlobMeta, Vec<u8>)> {
        encode_secure_flow_control(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureFlowControlBlobMeta, Vec<u8>)> {
        encode_secure_flow_control_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureFlowControlBlobMeta, Self)> {
        decode_secure_flow_control(data)
    }
}

pub fn select_secure_flow_control_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_flow_control(flow_control: &FlowControl, algorithm: CompressionAlgorithm) -> io::Result<(SecureFlowControlBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_flow_control(flow_control);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate flow-control blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_flow_control_blob_tag(
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
        magic = FLOW_CONTROL_BLOB_MAGIC,
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
        SecureFlowControlBlobMeta {
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

pub fn encode_secure_flow_control_auto(flow_control: &FlowControl, accept_encoding: &str) -> io::Result<(SecureFlowControlBlobMeta, Vec<u8>)> {
    let selected = select_secure_flow_control_algorithm(accept_encoding);
    encode_secure_flow_control(flow_control, selected)
}

pub fn decode_secure_flow_control(data: &[u8]) -> io::Result<(SecureFlowControlBlobMeta, FlowControl)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_flow_control_meta(&header, body.len())?;
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

    let expected_tag = compute_flow_control_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "flow-control blob HMAC mismatch",
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
            "flow-control blob digest mismatch",
        ));
    }

    let flow_control = deserialize_flow_control(&raw_payload)?;
    Ok((meta, flow_control))
}

fn serialize_flow_control(flow_control: &FlowControl) -> Vec<u8> {
    format!(
        "window-size={}\ninitial-window-size={}",
        flow_control.window_size, flow_control.initial_window_size
    ).into_bytes()
}

fn deserialize_flow_control(raw_payload: &[u8]) -> io::Result<FlowControl> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "flow-control payload is not valid UTF-8",
        )
    })?;

    let mut window_size = None::<i32>;
    let mut initial_window_size = None::<u32>;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid flow-control payload line '{}'", trimmed),
            )
        })?;

        match key.trim() {
            "window-size" => {
                window_size = Some(value.trim().parse::<i32>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid window-size")
                })?);
            }
            "initial-window-size" => {
                initial_window_size = Some(value.trim().parse::<u32>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid initial-window-size")
                })?);
            }
            _ => {}
        }
    }

    let window_size = window_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing window-size in flow-control payload",
        )
    })?;

    let initial_window_size = initial_window_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing initial-window-size in flow-control payload",
        )
    })?;

    if initial_window_size > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "initial-window-size exceeds i32::MAX",
        ));
    }

    Ok(FlowControl {
        window_size,
        initial_window_size,
    })
}

fn compute_flow_control_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(FLOW_CONTROL_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(FLOW_CONTROL_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_flow_control_meta(header: &str, body_len: usize) -> io::Result<SecureFlowControlBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != FLOW_CONTROL_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure flow-control blob magic mismatch",
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
                format!("invalid secure flow-control header line '{}'", line),
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
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure flow-control blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure flow-control blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure flow-control blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure flow-control blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure flow-control blob",
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
            "missing issued-at in secure flow-control blob",
        )
    })?;

    Ok(SecureFlowControlBlobMeta {
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
    fn test_flow_control_consume() {
        let mut fc = FlowControl::new(65535);
        assert!(fc.can_send(1000));
        fc.consume(1000).unwrap();
        assert_eq!(fc.window_size(), 64535);
    }

    #[test]
    fn test_flow_control_increase() {
        let mut fc = FlowControl::new(65535);
        fc.consume(1000).unwrap();
        fc.increase(1000).unwrap();
        assert_eq!(fc.window_size(), 65535);
    }

    #[test]
    fn test_flow_control_overflow() {
        let mut fc = FlowControl::new(i32::MAX as u32);
        assert!(fc.increase(1).is_err());
    }

    #[test]
    fn test_secure_flow_control_roundtrip_identity() {
        let fc = FlowControl::new(65535);
        let (_meta, blob) =
            encode_secure_flow_control(&fc, CompressionAlgorithm::Identity).unwrap();
        let (_decoded_meta, decoded_fc) = decode_secure_flow_control(&blob).unwrap();

        assert_eq!(decoded_fc.window_size(), fc.window_size());
        assert_eq!(decoded_fc.initial_window_size(), fc.initial_window_size());
    }
}