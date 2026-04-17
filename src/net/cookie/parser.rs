use super::cookie::{Cookie, SameSite};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const COOKIE_PARSER_BLOB_MAGIC: &str = "SINGULARITY_COOKIE_PARSER_BLOB_V1";
const COOKIE_PARSER_BLOB_CONTEXT: &str = "SINGULARITY_COOKIE_PARSER_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCookieHeaderBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub issued_at_unix: u64,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub pair_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidFormat,
    EmptyName,
    InvalidDate,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "Empty cookie header"),
            ParseError::InvalidFormat => write!(f, "Invalid cookie format"),
            ParseError::EmptyName => write!(f, "Empty cookie name"),
            ParseError::InvalidDate => write!(f, "Invalid date format"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_set_cookie(header: &str) -> Result<Cookie, ParseError> {
    let parts: Vec<&str> = header.split(';').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err(ParseError::Empty);
    }

    let (name, value) = parse_name_value(parts[0])?;
    let mut cookie = Cookie::new(name, value);
    for part in &parts[1..] {
        parse_attributes(&mut cookie, part)?;
    }

    Ok(cookie)
}

pub fn parse_cookie_header(header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in header.split(';').map(|s| s.trim()) {
        if let Ok((name, value)) = parse_name_value(pair) {
            cookies.insert(name, value);
        }
    }

    cookies
}

pub fn select_secure_cookie_parser_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_cookie_header(header: &str, algorithm: CompressionAlgorithm) -> io::Result<(SecureCookieHeaderBlobMeta, Vec<u8>)> {
    let cookie_map = parse_cookie_header(header);
    encode_secure_cookie_map(&cookie_map, algorithm)
}

pub fn encode_secure_cookie_header_auto(header: &str, accept_encoding: &str) -> io::Result<(SecureCookieHeaderBlobMeta, Vec<u8>)> {
    let algorithm = select_secure_cookie_parser_algorithm(accept_encoding);
    encode_secure_cookie_header(header, algorithm)
}

pub fn encode_secure_cookie_map(cookie_map: &HashMap<String, String>, algorithm: CompressionAlgorithm) -> io::Result<(SecureCookieHeaderBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_cookie_map(cookie_map);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure cookie parser nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_secure_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureCookieHeaderBlobMeta {
        algorithm: selected_algorithm,
        nonce_b64: pem::encode(&nonce),
        digest_b64: pem::encode(&digest),
        tag_b64: pem::encode(&tag),
        issued_at_unix,
        raw_size: raw_payload.len(),
        encoded_size: encoded_payload.len(),
        pair_count: cookie_map.len(),
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nissued-at={issued_at}\nraw-size={raw_size}\nencoded-size={encoded_size}\npair-count={pair_count}\n\n",
        magic = COOKIE_PARSER_BLOB_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        nonce = meta.nonce_b64,
        digest = meta.digest_b64,
        tag = meta.tag_b64,
        issued_at = meta.issued_at_unix,
        raw_size = meta.raw_size,
        encoded_size = meta.encoded_size,
        pair_count = meta.pair_count,
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded_payload);

    Ok((meta, out))
}

pub fn decode_secure_cookie_map(secure_blob: &[u8]) -> io::Result<(SecureCookieHeaderBlobMeta, HashMap<String, String>)> {
    let (header, body) = split_header_body(secure_blob)?;
    let meta = parse_secure_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nonce encoding in secure cookie parser blob",
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest encoding in secure cookie parser blob",
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tag encoding in secure cookie parser blob",
        )
    })?;

    let computed_tag = compute_secure_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob tag verification failed",
        ));
    }

    let decoded_payload = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        compression::decompress(meta.algorithm, body)?
    };

    if decoded_payload.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure cookie parser raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded_payload.len()
            ),
        ));
    }

    let computed_digest = sha256(&decoded_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser digest verification failed",
        ));
    }

    let cookie_map = deserialize_cookie_map(&decoded_payload, meta.pair_count)?;
    Ok((meta, cookie_map))
}

pub fn decode_secure_cookie_header(secure_blob: &[u8]) -> io::Result<(SecureCookieHeaderBlobMeta, String)> {
    let (meta, cookie_map) = decode_secure_cookie_map(secure_blob)?;
    Ok((meta, canonical_cookie_header(&cookie_map)))
}

fn parse_name_value(pair: &str) -> Result<(String, String), ParseError> {
    let mut parts = pair.splitn(2, '=');
    let name = parts.next().ok_or(ParseError::InvalidFormat)?.trim().to_string();
    if name.is_empty() {
        return Err(ParseError::EmptyName);
    }

    let value = parts.next().unwrap_or("").trim().to_string();
    Ok((name, value))
}

fn parse_attributes(cookie: &mut Cookie, attr: &str) -> Result<(), ParseError> {
    if attr.is_empty() {
        return Ok(());
    }

    let attr_lower = attr.to_lowercase();
    if attr_lower == "secure" {
        cookie.set_secure(true);
        return Ok(());
    }

    if attr_lower == "httponly" {
        cookie.set_http_only(true);
        return Ok(());
    }

    if let Some(eq_pos) = attr.find('=') {
        let (key, value) = attr.split_at(eq_pos);
        let key = key.trim().to_lowercase();
        let value = value[1..].trim();
        match key.as_str() {
            "domain" => {
                cookie.set_domain(value.to_string());
            }
            "path" => {
                cookie.set_path(Some(value.to_string()));
            }
            "expires" => {
                if let Ok(timestamp) = parse_expires(value) {
                    cookie.set_expires(Some(timestamp));
                }
            }
            "max-age" | "max_age" => {
                if let Ok(age) = value.parse::<i64>() {
                    cookie.set_max_age(Some(age));
                }
            }
            "samesite" => {
                let same_site = match value.to_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
                cookie.set_same_site(same_site);
            }
            _ => {}
        }
    }

    Ok(())
}

fn parse_expires(date_str: &str) -> Result<u64, ParseError> {
    let months: HashMap<&str, u32> = [
        ("jan", 1), ("feb", 2), ("mar", 3), ("apr", 4),
        ("may", 5), ("jun", 6), ("jul", 7), ("aug", 8),
        ("sep", 9), ("oct", 10), ("nov", 11), ("dec", 12),
    ].iter().cloned().collect();

    let cleaned = date_str.replace(",", "").replace("-", " ");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(ParseError::InvalidDate);
    }

    let day = parts[0].parse::<u32>().or_else(|_| parts[1].parse::<u32>()).map_err(|_| ParseError::InvalidDate)?;
    let month_str = parts[1].to_lowercase().chars().take(3).collect::<String>();
    let month = months .get(month_str.as_str()) .copied() .ok_or(ParseError::InvalidDate)?;
    let year = parts[2].parse::<u32>().or_else(|_| parts[3].parse::<u32>()).map_err(|_| ParseError::InvalidDate)?;
    let year = if year < 100 {
        if year < 70 { 2000 + year } else { 1900 + year }
    } else {
        year
    };

    let days_since_epoch = days_since_unix_epoch(year, month, day);
    Ok(days_since_epoch * 86400)
}

fn days_since_unix_epoch(year: u32, month: u32, day: u32) -> u64 {
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    let days_in_month = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += days_in_month[(m - 1) as usize];
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    days + day as u64 - 1
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn serialize_cookie_map(cookie_map: &HashMap<String, String>) -> Vec<u8> {
    let mut keys: Vec<&String> = cookie_map.keys().collect();
    keys.sort();
    let mut lines = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(value) = cookie_map.get(key) {
            lines.push(format!("{}={}", key, value));
        }
    }

    lines.join("\n").into_bytes()
}

fn deserialize_cookie_map(raw_payload: &[u8], expected_count: usize) -> io::Result<HashMap<String, String>> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    let mut parsed_count = 0usize;
    for line in payload.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (name, value) = parse_name_value(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse cookie pair in secure payload: {}", e),
            )
        })?;

        if map.insert(name, value).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate cookie name in secure payload",
            ));
        }

        parsed_count += 1;
    }

    if parsed_count != expected_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pair-count mismatch: expected {}, parsed {}",
                expected_count, parsed_count
            ),
        ));
    }

    Ok(map)
}

fn canonical_cookie_header(cookie_map: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = cookie_map.keys().collect();
    keys.sort();
    let mut parts = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(value) = cookie_map.get(key) {
            parts.push(format!("{}={}", key, value));
        }
    }

    parts.join("; ")
}

fn compute_secure_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(COOKIE_PARSER_BLOB_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    let hmac_key = sha256(&key_material);

    let mut msg = Vec::new();
    msg.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    msg.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &msg)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser header delimiter missing",
        )
    })?;

    let header = std::str::from_utf8(&data[..split_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser header is not utf-8",
        )
    })?.to_string();

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_blob_meta(header: &str, body_len: usize) -> io::Result<SecureCookieHeaderBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser magic missing",
        )
    })?;

    if magic != COOKIE_PARSER_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut issued_at_unix = None::<u64>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut pair_count = None::<usize>;
    for line in lines {
        let mut kv = line.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        match key {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding: {}", value),
                    )
                })?;
            }
            "nonce" => nonce_b64 = value.to_string(),
            "digest" => {
                if let Some(v) = value.strip_prefix("SHA-256=") {
                    digest_b64 = v.to_string();
                } else {
                    digest_b64 = value.to_string();
                }
            }
            "tag" => {
                if let Some(v) = value.strip_prefix("HMAC-SHA-256=") {
                    tag_b64 = v.to_string();
                } else {
                    tag_b64 = value.to_string();
                }
            }
            "issued-at" => {
                issued_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            "raw-size" => {
                raw_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "pair-count" => {
                pair_count = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid pair-count")
                })?);
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob missing nonce, digest, or tag",
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob missing issued-at",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob missing encoded-size",
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

    let pair_count = pair_count.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie parser blob missing pair-count",
        )
    })?;

    Ok(SecureCookieHeaderBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        issued_at_unix,
        raw_size,
        encoded_size,
        pair_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_set_cookie() {
        let cookie = parse_set_cookie("session=abc123; Path=/; Secure; HttpOnly").unwrap();
        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc123");
        assert!(cookie.is_secure());
        assert!(cookie.is_http_only());
    }

    #[test]
    fn test_parse_cookie_header() {
        let map = parse_cookie_header("a=1; b=2; c=3");
        assert_eq!(map.get("a").unwrap(), "1");
        assert_eq!(map.get("b").unwrap(), "2");
        assert_eq!(map.get("c").unwrap(), "3");
    }

    #[test]
    fn test_secure_cookie_map_roundtrip_identity() {
        let input: HashMap<String, String> = vec![
            ("session".to_string(), "abc123".to_string()),
            ("token".to_string(), "xyz789".to_string()),
        ]
        .into_iter()
        .collect();

        let (meta, blob) = encode_secure_cookie_map(&input, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.pair_count, 2);

        let (decoded_meta, output) = decode_secure_cookie_map(&blob).unwrap();
        assert_eq!(decoded_meta.pair_count, 2);
        assert_eq!(output.get("session").unwrap(), "abc123");
        assert_eq!(output.get("token").unwrap(), "xyz789");
    }

    #[test]
    fn test_secure_cookie_map_roundtrip_compressed() {
        let input: HashMap<String, String> = vec![
            ("a".to_string(), "1111111111".to_string()),
            ("b".to_string(), "2222222222".to_string()),
            ("c".to_string(), "3333333333".to_string()),
        ]
        .into_iter()
        .collect();

        let (meta, blob) = encode_secure_cookie_map(&input, CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.pair_count, 3);

        let (decoded_meta, output) = decode_secure_cookie_map(&blob).unwrap();
        assert_eq!(decoded_meta.pair_count, 3);
        assert_eq!(output.get("a").unwrap(), "1111111111");
        assert_eq!(output.get("b").unwrap(), "2222222222");
        assert_eq!(output.get("c").unwrap(), "3333333333");
    }

    #[test]
    fn test_secure_cookie_map_tamper_detected() {
        let input: HashMap<String, String> =
            vec![("session".to_string(), "abc123".to_string())]
                .into_iter()
                .collect();

        let (_, mut blob) = encode_secure_cookie_map(&input, CompressionAlgorithm::Identity).unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_cookie_map(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_secure_cookie_header_roundtrip() {
        let header = "z=9; a=1; m=5";
        let (_, blob) = encode_secure_cookie_header(header, CompressionAlgorithm::Identity).unwrap();

        let (_, decoded_header) = decode_secure_cookie_header(&blob).unwrap();
        assert_eq!(decoded_header, "a=1; m=5; z=9");
    }

    #[test]
    fn test_select_secure_cookie_parser_algorithm() {
        let selected = select_secure_cookie_parser_algorithm("br, gzip;q=0.8, identity;q=0.2");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let fallback = select_secure_cookie_parser_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}