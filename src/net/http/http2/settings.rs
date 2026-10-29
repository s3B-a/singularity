use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_SETTINGS_BLOB_V1";
const SETTINGS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_SETTINGS_BLOB_BINDING_V1";

pub const DEFAULT_LOCAL_MAX_CONCURRENT_STREAMS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureSettingsBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SettingId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    EnableConnectProtocol = 0x8,
    NoRfc7540Priorities = 0x9,
}

impl SettingId {
    pub fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1 => Some(SettingId::HeaderTableSize),
            0x2 => Some(SettingId::EnablePush),
            0x3 => Some(SettingId::MaxConcurrentStreams),
            0x4 => Some(SettingId::InitialWindowSize),
            0x5 => Some(SettingId::MaxFrameSize),
            0x6 => Some(SettingId::MaxHeaderListSize),
            0x8 => Some(SettingId::EnableConnectProtocol),
            0x9 => Some(SettingId::NoRfc7540Priorities),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    settings: HashMap<SettingId, u32>,
}

impl Settings {
    pub fn default() -> Self {
        let mut settings = HashMap::new();
        settings.insert(SettingId::HeaderTableSize, 4096);
        settings.insert(SettingId::EnablePush, 1);
        settings.insert(SettingId::MaxConcurrentStreams, u32::MAX);
        settings.insert(SettingId::InitialWindowSize, 65535);
        settings.insert(SettingId::MaxFrameSize, 16384);
        settings.insert(SettingId::MaxHeaderListSize, u32::MAX);
        settings.insert(SettingId::EnableConnectProtocol, 0);
        settings.insert(SettingId::NoRfc7540Priorities, 0);

        Self { settings }
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn local_defaults() -> Self {
        let mut settings = Self::default();
        settings.settings.insert(SettingId::MaxConcurrentStreams, DEFAULT_LOCAL_MAX_CONCURRENT_STREAMS);
        settings
    }

    pub fn get(&self, id: SettingId) -> u32 {
        *self.settings.get(&id).unwrap_or(&0)
    }

    pub fn set(&mut self, id: SettingId, value: u32) -> Result<(), String> {
        match id {
            SettingId::EnablePush => {
                if value > 1 {
                    return Err("ENABLE_PUSH must be 0 or 1".to_string());
                }
            }
            SettingId::InitialWindowSize => {
                if value > 2147483647 {
                    return Err("Initial window size too large".to_string());
                }
            }
            SettingId::MaxFrameSize => {
                if !(16384..=16777215).contains(&value) {
                    return Err("Max frame size out of range".to_string());
                }
            }
            SettingId::EnableConnectProtocol => {
                if value > 1 {
                    return Err("ENABLE_CONNECT_PROTOCOL must be 0 or 1".to_string());
                }
            }
            SettingId::NoRfc7540Priorities => {
                if value > 1 {
                    return Err("NO_RFC7540_PRIORITIES must be 0 or 1".to_string());
                }
            }
            _ => {}
        }

        self.settings.insert(id, value);
        Ok(())
    }

    pub fn header_table_size(&self) -> u32 {
        self.get(SettingId::HeaderTableSize)
    }

    pub fn enable_push(&self) -> bool {
        self.get(SettingId::EnablePush) == 1
    }

    pub fn max_concurrent_streams(&self) -> u32 {
        self.get(SettingId::MaxConcurrentStreams)
    }

    pub fn initial_window_size(&self) -> u32 {
        self.get(SettingId::InitialWindowSize)
    }

    pub fn max_frame_size(&self) -> u32 {
        self.get(SettingId::MaxFrameSize)
    }

    pub fn max_header_list_size(&self) -> u32 {
        self.get(SettingId::MaxHeaderListSize)
    }

    pub fn enable_connect_protocol(&self) -> bool {
        self.get(SettingId::EnableConnectProtocol) == 1
    }

    pub fn no_rfc7540_priorities(&self) -> bool {
        self.get(SettingId::NoRfc7540Priorities) == 1
    }

    pub fn allows_new_stream(&self, active_streams: usize) -> bool {
        active_streams < self.max_concurrent_streams() as usize
    }

    pub fn apply_update(&mut self, data: &[u8], is_first: bool) -> Result<(), (SettingId, String)> {
        if data.len() % 6 != 0 {
            return Err((SettingId::MaxFrameSize, "Invalid settings frame size".to_string()));
        }

        let mut updated = self.clone();
        for chunk in data.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            let Some(setting_id) = SettingId::from_u16(id) else {
                continue;
            };

            match setting_id {
                SettingId::EnableConnectProtocol if updated.enable_connect_protocol() && value == 0 => {
                    return Err((setting_id, "SETTINGS_ENABLE_CONNECT_PROTOCOL cannot change from 1 to 0".to_string()));
                }
                SettingId::NoRfc7540Priorities if !is_first && value != updated.get(setting_id) => {
                    return Err((setting_id, "SETTINGS_NO_RFC7540_PRIORITIES changed after the first SETTINGS frame".to_string()));
                }
                _ => {}
            }

            updated.set(setting_id, value).map_err(|e| (setting_id, e))?;
        }

        *self = updated;
        
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let ordered = [
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
            SettingId::EnableConnectProtocol,
            SettingId::NoRfc7540Priorities,
        ];

        for id in ordered {
            if let Some(&value) = self.settings.get(&id) {
                data.extend_from_slice(&(id as u16).to_be_bytes());
                data.extend_from_slice(&value.to_be_bytes());
            }
        }

        data
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() % 6 != 0 {
            return Err("Invalid settings frame size".to_string());
        }

        let mut settings = Settings::new();
        for chunk in data.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            if let Some(setting_id) = SettingId::from_u16(id) {
                settings.set(setting_id, value)?;
            }
        }

        Ok(settings)
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureSettingsBlobMeta, Vec<u8>)> {
        encode_secure_settings(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureSettingsBlobMeta, Vec<u8>)> {
        encode_secure_settings_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureSettingsBlobMeta, Self)> {
        decode_secure_settings(data)
    }
}

pub fn select_secure_settings_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_settings(settings: &Settings, algorithm: CompressionAlgorithm) -> io::Result<(SecureSettingsBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = settings.serialize();
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate settings blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_settings_blob_tag(
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
        magic = SETTINGS_BLOB_MAGIC,
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
        SecureSettingsBlobMeta {
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

pub fn encode_secure_settings_auto(settings: &Settings, accept_encoding: &str) -> io::Result<(SecureSettingsBlobMeta, Vec<u8>)> {
    let selected = select_secure_settings_algorithm(accept_encoding);
    encode_secure_settings(settings, selected)
}

pub fn decode_secure_settings(data: &[u8]) -> io::Result<(SecureSettingsBlobMeta, Settings)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_settings_meta(&header, body.len())?;
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

    let expected_tag = compute_settings_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "settings blob HMAC mismatch",
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
            "settings blob digest mismatch",
        ));
    }

    let settings = Settings::parse(&raw_payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid settings payload: {}", e),
        )
    })?;

    Ok((meta, settings))
}

fn compute_settings_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(SETTINGS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(SETTINGS_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_settings_meta(header: &str, body_len: usize) -> io::Result<SecureSettingsBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != SETTINGS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure settings blob magic mismatch",
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
                format!("invalid secure settings header line '{}'", line),
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
            "missing nonce in secure settings blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure settings blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure settings blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure settings blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure settings blob",
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
            "missing issued-at in secure settings blob",
        )
    })?;

    Ok(SecureSettingsBlobMeta {
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
    fn test_setting_validation() {
        let mut settings = Settings::new();

        assert!(settings.set(SettingId::EnablePush, 1).is_ok());
        assert!(settings.set(SettingId::EnablePush, 2).is_err());

        assert!(settings.set(SettingId::MaxFrameSize, 16_384).is_ok());
        assert!(settings.set(SettingId::MaxFrameSize, 16_383).is_err());
    }

    #[test]
    fn test_settings_parse_serialize_roundtrip() {
        let mut settings = Settings::new();
        settings.set(SettingId::InitialWindowSize, 1_000_000).unwrap();
        settings.set(SettingId::MaxConcurrentStreams, 128).unwrap();

        let wire = settings.serialize();
        let parsed = Settings::parse(&wire).unwrap();

        assert_eq!(parsed.initial_window_size(), 1_000_000);
        assert_eq!(parsed.max_concurrent_streams(), 128);
    }

    fn wire(entries: &[(SettingId, u32)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (id, value) in entries {
            data.extend_from_slice(&(*id as u16).to_be_bytes());
            data.extend_from_slice(&value.to_be_bytes());
        }
        data
    }

    #[test]
    fn test_apply_update_is_incremental() {
        let mut settings = Settings::new();
        settings.apply_update(&wire(&[(SettingId::MaxConcurrentStreams, 10)]), true).unwrap();
        settings.apply_update(&wire(&[(SettingId::InitialWindowSize, 1_000)]), false).unwrap();

        assert_eq!(settings.max_concurrent_streams(), 10);
        assert_eq!(settings.initial_window_size(), 1_000);
    }

    #[test]
    fn test_apply_update_is_atomic_and_reports_setting() {
        let mut settings = Settings::new();
        let err = settings.apply_update(&wire(&[
            (SettingId::MaxConcurrentStreams, 5),
            (SettingId::InitialWindowSize, u32::MAX),
        ]), true).unwrap_err();

        assert_eq!(err.0, SettingId::InitialWindowSize);
        assert_eq!(settings.max_concurrent_streams(), u32::MAX);
    }

    #[test]
    fn test_apply_update_ignores_unknown_settings() {
        let mut settings = Settings::new();
        let mut data = vec![0x00, 0xff, 0, 0, 0, 1];
        data.extend(wire(&[(SettingId::EnableConnectProtocol, 1)]));
        settings.apply_update(&data, true).unwrap();
        assert!(settings.enable_connect_protocol());
    }

    #[test]
    fn test_enable_connect_protocol_cannot_be_withdrawn() {
        let mut settings = Settings::new();
        settings.apply_update(&wire(&[(SettingId::EnableConnectProtocol, 1)]), true).unwrap();
        assert!(settings.apply_update(&wire(&[(SettingId::EnableConnectProtocol, 1)]), false).is_ok());

        let err = settings.apply_update(&wire(&[(SettingId::EnableConnectProtocol, 0)]), false).unwrap_err();
        assert_eq!(err.0, SettingId::EnableConnectProtocol);
        assert!(settings.apply_update(&wire(&[(SettingId::EnableConnectProtocol, 2)]), true).is_err());
    }

    #[test]
    fn test_no_rfc7540_priorities_fixed_after_first_settings() {
        let mut settings = Settings::new();
        settings.apply_update(&wire(&[(SettingId::NoRfc7540Priorities, 1)]), true).unwrap();
        assert!(settings.no_rfc7540_priorities());
        assert!(settings.apply_update(&wire(&[(SettingId::NoRfc7540Priorities, 1)]), false).is_ok());
        assert!(settings.apply_update(&wire(&[(SettingId::NoRfc7540Priorities, 0)]), false).is_err());
    }

    #[test]
    fn test_local_defaults_bound_concurrency() {
        let local = Settings::local_defaults();
        assert_eq!(local.max_concurrent_streams(), DEFAULT_LOCAL_MAX_CONCURRENT_STREAMS);
        assert!(local.allows_new_stream(99));
        assert!(!local.allows_new_stream(100));
        assert_eq!(Settings::default().max_concurrent_streams(), u32::MAX);
    }

    #[test]
    fn test_secure_settings_roundtrip_identity() {
        let settings = Settings::new();
        let (_meta, blob) = encode_secure_settings(&settings, CompressionAlgorithm::Identity).unwrap();
        let (_decoded_meta, decoded_settings) = decode_secure_settings(&blob).unwrap();

        assert_eq!(
            decoded_settings.initial_window_size(),
            settings.initial_window_size()
        );
        assert_eq!(decoded_settings.max_frame_size(), settings.max_frame_size());
    }

    #[test]
    fn test_secure_settings_tamper_detected() {
        let settings = Settings::new();
        let (_meta, mut blob) = encode_secure_settings(&settings, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_settings(&blob).is_err());
    }
}