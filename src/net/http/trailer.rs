use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead};
use std::time::{SystemTime, UNIX_EPOCH};

const TRAILER_HEADERS_BLOB_MAGIC: &str = "SINGULARITY_HTTP_TRAILER_HEADERS_BLOB_V1";
const TRAILER_HEADERS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_TRAILER_HEADERS_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureTrailerHeadersBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TrailerHeaders {
    headers: HashMap<String, String>,
    pub expected: Option<HashSet<String>>,
}

impl TrailerHeaders {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            expected: None,
        }
    }

    pub fn with_expected(trailer_value: &str) -> Self {
        let expected: HashSet<String> = trailer_value.split(',').map(|s| s.trim().to_lowercase()).collect();

        Self {
            headers: HashMap::new(),
            expected: Some(expected),
        }
    }

    pub fn add(&mut self, name: String, value: String) -> Result<(), io::Error> {
        let name_lower = name.to_lowercase();
        if is_forbidden_trailer_field(&name_lower) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Forbidden trailer field: {}", name),
            ));
        }

        if let Some(ref expected) = self.expected {
            if !expected.contains(&name_lower) {
                eprintln!("Warning: Unexpected trailer '{}' not in Trailer header", name);
            }
        }

        self.headers.insert(name, value);

        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn validate_expected(&self) -> Result<(), Vec<String>> {
        if let Some(ref expected) = self.expected {
            let received: HashSet<String> = self.headers.keys().map(|k| k.to_lowercase()).collect();
            let missing: Vec<String> = expected.difference(&received).cloned().collect();
            if !missing.is_empty() {
                return Err(missing);
            }
        }

        Ok(())
    }

    pub fn parse<R: BufRead>(reader: &mut R, has_trailer_header: bool, trailer_value: Option<&str>) -> Result<Self, io::Error> {
        let mut trailers = if let Some(value) = trailer_value {
            Self::with_expected(value)
        } else {
            Self::new()
        };

        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if line.trim().is_empty() || bytes_read == 0 {
                break;
            }

            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                trailers.add(name, value)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Malformed trailer line: {}", line.trim()),
                ));
            }
        }

        if has_trailer_header {
            if let Err(missing) = trailers.validate_expected() {
                for field in missing {
                    eprintln!("Warning: Expected trailer '{}' was not received", field);
                }
            }
        }

        Ok(trailers)
    }

    pub fn into_map(self) -> HashMap<String, String> {
        self.headers
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureTrailerHeadersBlobMeta, Vec<u8>)> {
        encode_secure_trailer_headers(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureTrailerHeadersBlobMeta, Vec<u8>)> {
        encode_secure_trailer_headers_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureTrailerHeadersBlobMeta, Self)> {
        decode_secure_trailer_headers(data)
    }
}

pub fn select_secure_trailer_headers_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_trailer_headers(trailers: &TrailerHeaders, algorithm: CompressionAlgorithm) -> io::Result<(SecureTrailerHeadersBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_trailer_headers(trailers);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate trailer headers blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_trailer_headers_blob_tag(
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
        magic = TRAILER_HEADERS_BLOB_MAGIC,
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
        SecureTrailerHeadersBlobMeta {
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

pub fn encode_secure_trailer_headers_auto(trailers: &TrailerHeaders, accept_encoding: &str) -> io::Result<(SecureTrailerHeadersBlobMeta, Vec<u8>)> {
    let selected = select_secure_trailer_headers_algorithm(accept_encoding);
    encode_secure_trailer_headers(trailers, selected)
}

pub fn decode_secure_trailer_headers(data: &[u8]) -> io::Result<(SecureTrailerHeadersBlobMeta, TrailerHeaders)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_trailer_headers_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid trailer nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid trailer digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid trailer tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailer digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_trailer_headers_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailer headers blob HMAC mismatch",
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
                "trailer raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailer headers blob digest mismatch",
        ));
    }

    let trailers = deserialize_trailer_headers(&raw_payload)?;
    Ok((meta, trailers))
}

fn serialize_trailer_headers(trailers: &TrailerHeaders) -> Vec<u8> {
    let mut lines = Vec::new();
    if let Some(expected) = &trailers.expected {
        let mut expected_fields: Vec<&String> = expected.iter().collect();
        expected_fields.sort();
        for field in expected_fields {
            lines.push(format!("e={}", pem::encode(field.as_bytes())));
        }
    }

    let mut entries: Vec<(&String, &String)> = trailers.headers.iter().collect();
    entries.sort_by(|(ka, va), (kb, vb)| ka.cmp(kb).then(va.cmp(vb)));
    for (name, value) in entries {
        lines.push(format!(
            "h={}|{}",
            pem::encode(name.as_bytes()),
            pem::encode(value.as_bytes())
        ));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_trailer_headers(raw_payload: &[u8]) -> io::Result<TrailerHeaders> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "trailer payload is not valid UTF-8",
        )
    })?;

    let mut trailers = TrailerHeaders::new();
    let mut expected = HashSet::new();
    let mut has_expected = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("e=") {
            let field = String::from_utf8(pem::decode(v).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid expected trailer field encoding: {}", e),
                )
            })?).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected trailer field is not valid UTF-8",
                )
            })?;

            expected.insert(field.to_lowercase());
            has_expected = true;
            continue;
        }

        let payload = trimmed.strip_prefix("h=").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid trailer payload line '{}'", trimmed),
            )
        })?;

        let (name_b64, value_b64) = payload.split_once('|').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid trailer header payload line '{}'", trimmed),
            )
        })?;

        let name = String::from_utf8(pem::decode(name_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid trailer header name encoding: {}", e),
            )
        })?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "trailer name is not valid UTF-8"))?;

        let value = String::from_utf8(pem::decode(value_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid trailer header value encoding: {}", e),
            )
        })?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "trailer value is not valid UTF-8"))?;

        let name_lower = name.to_lowercase();
        if is_forbidden_trailer_field(&name_lower) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("forbidden trailer field in payload: {}", name),
            ));
        }

        trailers.headers.insert(name, value);
    }

    if has_expected {
        trailers.expected = Some(expected);
    }

    Ok(trailers)
}

fn compute_trailer_headers_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(TRAILER_HEADERS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(TRAILER_HEADERS_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_trailer_headers_meta(header: &str, body_len: usize) -> io::Result<SecureTrailerHeadersBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != TRAILER_HEADERS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure trailer headers blob magic mismatch",
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

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure trailer header line '{}'", line),
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
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid digest header"))?.to_string();
                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid tag header"))?.to_string();
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
            "missing nonce in secure trailer headers blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure trailer headers blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure trailer headers blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure trailer headers blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure trailer headers blob",
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
            "missing issued-at in secure trailer headers blob",
        )
    })?;

    Ok(SecureTrailerHeadersBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

pub fn is_forbidden_trailer_field(field_name: &str) -> bool {
    const FORBIDDEN_FIELDS: &[&str] = &[
        "transfer-encoding",
        "content-length",
        "trailer",
        "host",
        "cache-control",
        "expect",
        "max-forwards",
        "pragma",
        "range",
        "te",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
        "cookie",
        "set-cookie",
        "content-encoding",
        "content-type",
        "content-range",
        "connection",
        "keep-alive",
        "upgrade",
        "via",
        "warning",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        "age",
        "expires",
        "date",
        "retry-after",
    ];

    let normalized = field_name.trim().to_ascii_lowercase();
    FORBIDDEN_FIELDS.contains(&normalized.as_str())
}

pub mod common {
    pub const CONTENT_MD5: &str = "Content-MD5";
    pub const X_CONTENT_SHA256: &str = "X-Content-SHA256";
    pub const X_CONTENT_SHA512: &str = "X-Content-SHA512";
    pub const DIGEST: &str = "Digest";
    pub const X_TRAILER_STATUS: &str = "X-Trailer-Status";
    pub const X_PROCESSING_TIME: &str = "X-Processing-Time";
    pub const SERVER_TIMING: &str = "Server-Timing";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_trailer_creation() {
        let mut trailers = TrailerHeaders::new();
        assert!(trailers.is_empty());

        trailers
            .add("X-Custom".to_string(), "value".to_string())
            .unwrap();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_forbidden_trailer_fields() {
        assert!(is_forbidden_trailer_field("transfer-encoding"));
        assert!(is_forbidden_trailer_field("content-length"));
        assert!(is_forbidden_trailer_field("host"));
        assert!(is_forbidden_trailer_field("authorization"));
        assert!(is_forbidden_trailer_field("cookie"));

        assert!(!is_forbidden_trailer_field("x-custom-header"));
        assert!(!is_forbidden_trailer_field("content-md5"));
        assert!(!is_forbidden_trailer_field("digest"));
    }

    #[test]
    fn test_trailer_validation_forbidden() {
        let mut trailers = TrailerHeaders::new();

        let result = trailers.add("Content-Length".to_string(), "100".to_string());
        assert!(result.is_err());
        assert_eq!(trailers.len(), 0);
    }

    #[test]
    fn test_trailer_with_expected() {
        let trailers = TrailerHeaders::with_expected("X-Checksum, X-Status");
        assert_eq!(trailers.expected.as_ref().unwrap().len(), 2);
        assert!(trailers.expected.as_ref().unwrap().contains("x-checksum"));
        assert!(trailers.expected.as_ref().unwrap().contains("x-status"));
    }

    #[test]
    fn test_trailer_parse() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);

        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers.get("X-Checksum"), Some(&"abc123".to_string()));
        assert_eq!(trailers.get("X-Status"), Some(&"OK".to_string()));
    }

    #[test]
    fn test_trailer_parse_with_expected() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);

        let trailers =
            TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status")).unwrap();
        assert_eq!(trailers.len(), 2);
        assert!(trailers.validate_expected().is_ok());
    }

    #[test]
    fn test_trailer_parse_missing_expected() {
        let data = b"X-Checksum: abc123\r\n\r\n";
        let mut cursor = Cursor::new(data);

        let trailers =
            TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status")).unwrap();
        assert_eq!(trailers.len(), 1);

        let result = trailers.validate_expected();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), vec!["x-status"]);
    }

    #[test]
    fn test_trailer_parse_forbidden_field() {
        let data = b"Content-Length: 100\r\n\r\n";
        let mut cursor = Cursor::new(data);

        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_trailer_parse_malformed() {
        let data = b"Invalid Line Without Colon\r\n\r\n";
        let mut cursor = Cursor::new(data);

        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_common_trailer_fields() {
        use super::common::*;

        assert!(!is_forbidden_trailer_field(
            CONTENT_MD5.to_lowercase().as_str()
        ));
        assert!(!is_forbidden_trailer_field(
            X_CONTENT_SHA256.to_lowercase().as_str()
        ));
        assert!(!is_forbidden_trailer_field(DIGEST.to_lowercase().as_str()));
        assert!(!is_forbidden_trailer_field(
            SERVER_TIMING.to_lowercase().as_str()
        ));
    }

    #[test]
    fn test_secure_trailer_blob_roundtrip_identity() {
        let mut trailers = TrailerHeaders::with_expected("X-Checksum, X-Status");
        trailers
            .add("X-Checksum".to_string(), "abc123".to_string())
            .unwrap();
        trailers
            .add("X-Status".to_string(), "OK".to_string())
            .unwrap();

        let (meta, blob) = trailers
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = TrailerHeaders::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.get("X-Checksum"), Some(&"abc123".to_string()));
        assert_eq!(restored.get("X-Status"), Some(&"OK".to_string()));
        assert!(restored
            .expected
            .as_ref()
            .unwrap()
            .contains("x-checksum"));
        assert!(restored.expected.as_ref().unwrap().contains("x-status"));
    }

    #[test]
    fn test_secure_trailer_blob_roundtrip_auto() {
        let mut trailers = TrailerHeaders::new();
        trailers
            .add("X-Content-SHA256".to_string(), "deadbeef".to_string())
            .unwrap();

        let (meta, blob) = trailers
            .to_secure_blob_auto("gzip, br;q=0.5, identity;q=0.1")
            .unwrap();
        assert!(meta.encoded_size > 0);

        let (decoded_meta, restored) = decode_secure_trailer_headers(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, meta.algorithm);
        assert_eq!(restored.get("X-Content-SHA256"), Some(&"deadbeef".to_string()));
    }

    #[test]
    fn test_secure_trailer_blob_tamper_detection() {
        let mut trailers = TrailerHeaders::new();
        trailers
            .add("X-Trailer-Status".to_string(), "ok".to_string())
            .unwrap();

        let (_, mut blob) = trailers
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = TrailerHeaders::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}