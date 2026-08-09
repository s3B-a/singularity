pub mod gzip;
pub mod deflate;
pub mod brotli;
pub mod zstd;
pub mod utils;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const COMPRESSION_BLOB_MAGIC: &str = "SINGULARITY_HTTP_COMPRESSION_BLOB_V1";
const COMPRESSION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_COMPRESSION_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCompressionBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

impl CompressionAlgorithm {
    pub fn content_encoding(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
            CompressionAlgorithm::Identity => "identity",
        }
    }

    pub fn from_content_encoding(encoding: &str) -> Option<Self> {
        match encoding {
            "gzip" | "x-gzip" => Some(CompressionAlgorithm::Gzip),
            "deflate" => Some(CompressionAlgorithm::Deflate),
            "br" => Some(CompressionAlgorithm::Brotli),
            "zstd" => Some(CompressionAlgorithm::Zstd),
            "identity" => Some(CompressionAlgorithm::Identity),
            _ => None,
        }
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gz",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zst",
            CompressionAlgorithm::Identity => "",
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            CompressionAlgorithm::Gzip => 4,
            CompressionAlgorithm::Deflate => 3,
            CompressionAlgorithm::Brotli => 5,
            CompressionAlgorithm::Zstd => 6,
            CompressionAlgorithm::Identity => 0,
        }
    }

    pub fn is_implemented(&self) -> bool {
        match self {
            CompressionAlgorithm::Gzip => true,
            CompressionAlgorithm::Deflate => true,
            CompressionAlgorithm::Brotli => true,
            CompressionAlgorithm::Zstd => true,
            CompressionAlgorithm::Identity => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    Fast,
    Default,
    Best,
    Custom(u8),
}

impl CompressionLevel {
    pub fn deflate_level(&self) -> u8 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 9,
            CompressionLevel::Custom(level) => (*level).min(9),
        }
    }

    pub fn brotli_level(&self) -> u8 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 11,
            CompressionLevel::Custom(level) => (*level).min(11),
        }
    }

    pub fn zstd_level(&self) -> i32 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 3,
            CompressionLevel::Best => 22,
            CompressionLevel::Custom(level) => (*level as i32).min(22),
        }
    }
}

pub trait Compressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>>;
    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<Vec<u8>>;
    fn reset(&mut self);
}

pub trait Decompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>>;
    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<Vec<u8>>;
    fn reset(&mut self);
}

#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub algorithms: Vec<CompressionAlgorithm>,
    pub min_size: usize,
    pub max_size: Option<usize>,
    pub level: CompressionLevel,
    pub excluded_content_types: Vec<String>,
    pub prefer_algorithm: Option<CompressionAlgorithm>,
}

impl CompressionConfig {
    pub fn should_compress_content_type(&self, content_type: &str) -> bool {
        let content_type_lower = content_type.to_lowercase();
        for excluded in &self.excluded_content_types {
            if content_type_lower.starts_with(&excluded.to_lowercase()) {
                return false;
            }
        }

        true
    }

    pub fn should_compress_size(&self, size: usize) -> bool {
        if size < self.min_size {
            return false;
        }

        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        true
    }

    pub fn negotiate_algorithm(&self, accpet_encoding: &str) -> Option<CompressionAlgorithm> {
        let accepted = parse_accept_encoding(accpet_encoding);
        for algo in &self.algorithms {
            if accepted.iter().any(|(enc, _)| enc == algo) {
                if algo.is_implemented() {
                    return Some(*algo);
                }
            }
        }

        if accepted.iter().any(|(enc, _)| *enc == CompressionAlgorithm::Identity) {
            return Some(CompressionAlgorithm::Identity);
        }

        None
    }
}

pub fn parse_accept_encoding(accept_encoding: &str) -> Vec<(CompressionAlgorithm, f32)> {
    let mut encodings = Vec::new();
    for part in accept_encoding.split(',') {
        let part = part.trim();
        let (encoding, quality) = if let Some((enc, q)) = part.split_once(';') {
            let enc = enc.trim();
            let q_value = q.trim().strip_prefix("q=").and_then(|v| v.parse::<f32>().ok()).unwrap_or(1.0);
            (enc, q_value)
        } else {
            (part, 1.0)
        };

        if let Some(algo) = CompressionAlgorithm::from_content_encoding(encoding) {
            encodings.push((algo, quality));
        }
    }

    encodings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    encodings
}

pub fn select_secure_compression_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_compressed_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureCompressionBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = data.to_vec();
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate compression blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_compression_blob_tag(
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
        magic = COMPRESSION_BLOB_MAGIC,
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
        SecureCompressionBlobMeta {
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

pub fn encode_secure_compressed_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureCompressionBlobMeta, Vec<u8>)> {
    let selected = select_secure_compression_algorithm(accept_encoding);
    encode_secure_compressed_payload(data, selected)
}

pub fn decode_secure_compressed_payload(blob: &[u8]) -> io::Result<(SecureCompressionBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(blob)?;
    let meta = parse_secure_compression_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression blob digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_compression_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression blob HMAC mismatch",
        ));
    }

    let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        decompress(meta.algorithm, body)?
    };

    if raw_payload.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compression raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

pub fn compress(algorithm: CompressionAlgorithm, data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Gzip => gzip::compress(data, level),
        CompressionAlgorithm::Deflate => deflate::compress(data, level),
        CompressionAlgorithm::Brotli => brotli::compress(data, level),
        CompressionAlgorithm::Zstd => zstd::compress(data, level),
        CompressionAlgorithm::Identity => Ok(data.to_vec()),
    }
}

pub const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

pub fn decompress(algorithm: CompressionAlgorithm, data: &[u8]) -> io::Result<Vec<u8>> {
    decompress_bounded(algorithm, data, MAX_DECOMPRESSED_SIZE)
}

pub fn decompress_bounded(algorithm: CompressionAlgorithm, data: &[u8], max_output_size: usize) -> io::Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Gzip => gzip::decompress_bounded(data, max_output_size),
        CompressionAlgorithm::Deflate => deflate::decompress_bounded(data, max_output_size),
        CompressionAlgorithm::Brotli => brotli::decompress_bounded(data, max_output_size),
        CompressionAlgorithm::Zstd => zstd::decompress_bounded(data, max_output_size),
        CompressionAlgorithm::Identity => {
            if data.len() > max_output_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "payload exceeds maximum allowed size of {} bytes",
                        max_output_size
                    ),
                ));
            }

            Ok(data.to_vec())
        }
    }
}

pub fn detect_algorithm(data: &[u8]) -> Option<CompressionAlgorithm> {
    if data.len() < 2 {
        return None;
    }

    if data[0] == 0x1f && data[1] == 0x8b {
        return Some(CompressionAlgorithm::Gzip);
    }

    if data.len() >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        return Some(CompressionAlgorithm::Zstd);
    }

    if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA) {
        return Some(CompressionAlgorithm::Deflate);
    }

    None
}

fn compute_compression_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(COMPRESSION_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(COMPRESSION_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "compression blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "compression blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "compression blob missing header/body separator",
    ))
}

fn parse_secure_compression_blob_meta(header: &str, body_len: usize) -> io::Result<SecureCompressionBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != COMPRESSION_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid compression blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid compression header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", v.trim()),
                        )
                    },
                )?;
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
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in compression blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in compression blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in compression blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in compression blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in compression blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in compression blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compression encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureCompressionBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Default for CompressionLevel {
    fn default() -> Self {
        CompressionLevel::Default
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithms: vec![
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Zstd,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Deflate,
            ],
            min_size: 860,
            max_size: Some(10 * 1024 * 1024),
            level: CompressionLevel::Default,
            excluded_content_types: vec![
                // Images
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "image/webp".to_string(),
                "image/avif".to_string(),
                // Video
                "video/".to_string(),
                // Audio
                "audio/".to_string(),
                // Already compressed
                "application/zip".to_string(),
                "application/gzip".to_string(),
                "application/x-bzip2".to_string(),
                "application/x-7z-compressed".to_string(),
                "application/x-rar-compressed".to_string(),
            ],
            prefer_algorithm: Some(CompressionAlgorithm::Brotli),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_content_encoding() {
        assert_eq!(CompressionAlgorithm::Gzip.content_encoding(), "gzip");
        assert_eq!(CompressionAlgorithm::Deflate.content_encoding(), "deflate");
        assert_eq!(CompressionAlgorithm::Brotli.content_encoding(), "br");
        assert_eq!(CompressionAlgorithm::Zstd.content_encoding(), "zstd");
        assert_eq!(CompressionAlgorithm::Identity.content_encoding(), "identity");
    }

    #[test]
    fn test_algorithm_from_content_encoding() {
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("gzip"),
            Some(CompressionAlgorithm::Gzip)
        );
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("x-gzip"),
            Some(CompressionAlgorithm::Gzip)
        );
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("br"),
            Some(CompressionAlgorithm::Brotli)
        );
        assert_eq!(CompressionAlgorithm::from_content_encoding("unknown"), None);
    }

    #[test]
    fn test_compression_level_values() {
        assert_eq!(CompressionLevel::Fast.deflate_level(), 1);
        assert_eq!(CompressionLevel::Default.deflate_level(), 6);
        assert_eq!(CompressionLevel::Best.deflate_level(), 9);
        assert_eq!(CompressionLevel::Custom(5).deflate_level(), 5);
        assert_eq!(CompressionLevel::Custom(20).deflate_level(), 9); // clamped
    }

    #[test]
    fn test_parse_accept_encoding() {
        let result = parse_accept_encoding("gzip, deflate, br");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, CompressionAlgorithm::Gzip);
        assert_eq!(result[0].1, 1.0);
    }

    #[test]
    fn test_parse_accept_encoding_with_quality() {
        let result = parse_accept_encoding("gzip;q=0.8, br;q=1.0, deflate;q=0.5");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, CompressionAlgorithm::Brotli);
        assert_eq!(result[0].1, 1.0);
        assert_eq!(result[1].0, CompressionAlgorithm::Gzip);
        assert_eq!(result[1].1, 0.8);
    }

    #[test]
    fn test_config_should_compress_content_type() {
        let config = CompressionConfig::default();

        assert!(config.should_compress_content_type("text/html"));
        assert!(config.should_compress_content_type("application/json"));
        assert!(!config.should_compress_content_type("image/jpeg"));
        assert!(!config.should_compress_content_type("video/mp4"));
    }

    #[test]
    fn test_config_should_compress_size() {
        let config = CompressionConfig::default();

        assert!(!config.should_compress_size(500)); // Too small
        assert!(config.should_compress_size(1000)); // Good size
        assert!(!config.should_compress_size(20 * 1024 * 1024)); // Too large
    }

    #[test]
    fn test_detect_gzip() {
        let gzip_header = vec![0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(
            detect_algorithm(&gzip_header),
            Some(CompressionAlgorithm::Gzip)
        );
    }

    #[test]
    fn test_detect_zstd() {
        let zstd_header = vec![0x28, 0xB5, 0x2F, 0xFD];
        assert_eq!(
            detect_algorithm(&zstd_header),
            Some(CompressionAlgorithm::Zstd)
        );
    }

    #[test]
    fn test_algorithm_priority() {
        assert!(CompressionAlgorithm::Brotli.priority() > CompressionAlgorithm::Gzip.priority());
        assert!(CompressionAlgorithm::Zstd.priority() > CompressionAlgorithm::Deflate.priority());
    }

    #[test]
    fn test_select_secure_compression_algorithm() {
        let selected = select_secure_compression_algorithm("gzip;q=0.7, br;q=1.0, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Brotli);
    }

    #[test]
    fn test_secure_compressed_payload_roundtrip_identity() {
        let payload = b"compression secure payload identity path".to_vec();
        let (meta, blob) =
            encode_secure_compressed_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_payload) = decode_secure_compressed_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_secure_compressed_payload_roundtrip_gzip() {
        let payload =
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();

        let (meta, blob) =
            encode_secure_compressed_payload(&payload, CompressionAlgorithm::Gzip).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, decoded_payload) = decode_secure_compressed_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_secure_compressed_payload_tamper_detection() {
        let payload = b"tamper-me".to_vec();
        let (_, mut blob) =
            encode_secure_compressed_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_compressed_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
