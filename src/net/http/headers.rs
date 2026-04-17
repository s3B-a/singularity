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

const HEADERS_BLOB_MAGIC: &str = "SINGULARITY_HTTP_HEADERS_BLOB_V1";
const HEADERS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_HEADERS_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHeadersBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct Headers {
    headers: HashMap<String, Vec<String>>,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = Self::normalize_name(name.into());
        self.headers.insert(name, vec![value.into()]);
    }

    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = Self::normalize_name(name.into());
        self.headers.entry(name).or_insert_with(Vec::new).push(value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = Self::normalize_name(name.to_string());
        self.headers.get(&name).and_then(|values| values.first().map(|s| s.as_str()))
    }

    pub fn get_all(&self, name: &str) -> Option<&[String]> {
        let name = Self::normalize_name(name.to_string());
        self.headers.get(&name).map(|values| values.as_slice())
    }

    pub fn contains(&self, name: &str) -> bool {
        let name = Self::normalize_name(name.to_string());
        self.headers.contains_key(&name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        let name = Self::normalize_name(name.to_string());
        self.headers.remove(&name)
    }

    pub fn names(&self) -> Vec<String> {
        self.headers.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.headers.iter()
    }

    fn normalize_name(name: String) -> String {
        name.trim().to_ascii_lowercase()
    }

    pub fn parse(lines: &[String]) -> Self {
        let mut headers = Self::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.append(name.trim(), value.trim());
            }
        }

        headers
    }

    pub fn format(&self) -> String {
        let mut result = String::new();
        for (name, val) in &self.headers {
            for v in val {
                result.push_str(&format!("{}: {}\r\n", Self::capitalize_name(name), v));
            }
        }

        result
    }

    fn capitalize_name(name: &str) -> String {
        name.split('-').map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        }).collect::<Vec<_>>().join("-")
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length").and_then(|v| v.parse().ok())
    }

    pub fn transfer_encoding(&self) -> Option<&str> {
        self.get("transfer-encoding")
    }

    pub fn is_keep_alive(&self) -> bool {
        self.get("connection").map(|v| v.to_lowercase() == "keep-alive").unwrap_or(false)
    }

    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding").map(|v| v.to_lowercase().contains("chunked")).unwrap_or(false)
    }

    pub fn content_encoding(&self) -> Option<&str> {
        self.get("content-encoding")
    }

    pub fn has_content_encoding(&self) -> bool {
        self.content_encoding().map(|v| !v.trim().is_empty() && !v.eq_ignore_ascii_case("identity")).unwrap_or(false)
    }

    pub fn set_content_encoding(&mut self, encoding: &str) {
        self.insert("Content-Encoding", encoding);
    }

    pub fn remove_content_encoding(&mut self) {
        self.remove("content-encoding");
    }

    pub fn accept_encoding(&self) -> Option<&str> {
        self.get("accept-encoding")
    }

    pub fn set_accept_encoding(&mut self, value: &str) {
        self.insert("Accept-Encoding", value);
    }

    pub fn digest(&self) -> Option<&str> {
        self.get("digest")
    }

    pub fn has_sha256_digest(&self) -> bool {
        self.digest().map(|v| {
            v.split(',').any(|part| part.trim().to_ascii_lowercase().starts_with("sha-256="))
        }).unwrap_or(false)
    }

    pub fn set_digest_sha256_b64(&mut self, digest_b64: &str) {
        self.insert("Digest", format!("SHA-256={}", digest_b64));
    }

    pub fn into_map(self) -> HashMap<String, String> {
        self.headers.into_iter().map(|(k, v)| (k, v.join(", "))).collect()
    }

    pub fn ensure_keep_alive(&mut self) {
        if !self.contains("connection") {
            self.insert("Connection", "keep-alive");
        }
    }

    pub fn has_keep_alive(&self) -> bool {
        self.get("connection").map(|v| v.to_lowercase().contains("keep-alive")).unwrap_or(false)
    }

    pub fn set_connection_type(&mut self, connection_type: &str) {
        self.insert("Connection", connection_type);
    }

    pub fn connection_type(&self) -> String {
        self.get("connection").unwrap_or("keep-alive").to_string()
    }

    pub fn clone_for_connection(&self) -> Self {
        let mut new_headers = self.clone();
        new_headers.ensure_keep_alive();
        new_headers
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHeadersBlobMeta, Vec<u8>)> {
        encode_secure_headers(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHeadersBlobMeta, Vec<u8>)> {
        encode_secure_headers_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHeadersBlobMeta, Self)> {
        decode_secure_headers(data)
    }
}

pub fn select_secure_headers_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_headers(headers: &Headers, algorithm: CompressionAlgorithm) -> io::Result<(SecureHeadersBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_headers(headers);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate headers blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_headers_blob_tag(
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
        magic = HEADERS_BLOB_MAGIC,
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
        SecureHeadersBlobMeta {
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

pub fn encode_secure_headers_auto(headers: &Headers, accept_encoding: &str) -> io::Result<(SecureHeadersBlobMeta, Vec<u8>)> {
    let selected = select_secure_headers_algorithm(accept_encoding);
    encode_secure_headers(headers, selected)
}

pub fn decode_secure_headers(data: &[u8]) -> io::Result<(SecureHeadersBlobMeta, Headers)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_headers_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid headers blob nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid headers blob digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid headers blob tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "headers blob digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_headers_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "headers blob HMAC mismatch",
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
                "headers blob raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "headers blob digest mismatch",
        ));
    }

    let headers = deserialize_headers(&raw_payload)?;
    Ok((meta, headers))
}

fn serialize_headers(headers: &Headers) -> Vec<u8> {
    let mut keys: Vec<&String> = headers.headers.keys().collect();
    keys.sort();
    let mut lines = Vec::new();
    for key in keys {
        if let Some(values) = headers.headers.get(key) {
            for value in values {
                lines.push(format!(
                    "h={}|{}",
                    pem::encode(key.as_bytes()),
                    pem::encode(value.as_bytes())
                ));
            }
        }
    }

    lines.join("\n").into_bytes()
}

fn deserialize_headers(raw_payload: &[u8]) -> io::Result<Headers> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "headers payload is not valid UTF-8",
        )
    })?;

    let mut headers = Headers::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let payload = trimmed.strip_prefix("h=").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid headers payload line '{}'", trimmed),
            )
        })?;

        let (name_b64, value_b64) = payload.split_once('|').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid header payload line '{}'", trimmed),
            )
        })?;

        let name = String::from_utf8(pem::decode(name_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid header name encoding: {}", e),
            )
        })?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header name is not valid UTF-8"))?;

        let value = String::from_utf8(pem::decode(value_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid header value encoding: {}", e),
            )
        })?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header value is not valid UTF-8"))?;

        headers.append(name, value);
    }

    Ok(headers)
}

fn compute_headers_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HEADERS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HEADERS_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "headers blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "headers blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "headers blob missing header/body separator",
    ))
}

fn parse_secure_headers_meta(header: &str, body_len: usize) -> io::Result<SecureHeadersBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HEADERS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid headers blob magic",
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
                format!("invalid headers blob header line '{}'", line),
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
                })?;

                digest_b64 = Some(parsed.to_string());
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?;

                tag_b64 = Some(parsed.to_string());
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in headers blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in headers blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in headers blob")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in headers blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in headers blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in headers blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in headers blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in headers blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in headers blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "headers blob encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHeadersBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_headers_blob_roundtrip_identity() {
        let mut headers = Headers::new();
        headers.insert("Content-Type", "application/json");
        headers.append("Set-Cookie", "a=1");
        headers.append("Set-Cookie", "b=2");
        headers.insert("Accept-Encoding", "gzip, br");

        let (meta, blob) = headers
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.encoded_size + 1, blob.len() - blob.iter().position(|&b| b == b'\n').unwrap_or(0));

        let (decoded_meta, restored) = Headers::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.get("content-type"), Some("application/json"));
        assert_eq!(restored.get_all("set-cookie").unwrap().len(), 2);
    }

    #[test]
    fn test_secure_headers_blob_roundtrip_auto() {
        let mut headers = Headers::new();
        headers.insert("X-Test", "value");
        headers.insert("Connection", "keep-alive");

        let (meta, blob) = headers.to_secure_blob_auto("gzip, identity;q=0.1").unwrap();
        assert!(meta.encoded_size > 0);

        let (decoded_meta, restored) = decode_secure_headers(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, meta.algorithm);
        assert_eq!(restored.get("x-test"), Some("value"));
        assert_eq!(restored.get("connection"), Some("keep-alive"));
    }

    #[test]
    fn test_secure_headers_blob_tamper_detection() {
        let mut headers = Headers::new();
        headers.insert("A", "B");

        let (_, mut blob) = headers.to_secure_blob(CompressionAlgorithm::Identity).unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = Headers::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}