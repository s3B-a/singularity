pub mod cookie;
pub mod jar;
pub mod parser;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub use cookie::{Cookie, SameSite};
pub use jar::CookieJar;
pub use parser::{parse_cookie_header, parse_set_cookie, ParseError};

pub const COOKIE_SECURE_ENVELOPE_MAGIC: &str = "SINGULARITY_COOKIE_SECURE_ENVELOPE_V1";
const COOKIE_SECURE_ENVELOPE_CONTEXT: &str = "SINGULARITY_COOKIE_SECURE_ENVELOPE_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCookieEnvelopeMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
    pub cookie_count: usize,
}

pub fn select_secure_cookie_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_cookie_jar(jar: &CookieJar, algorithm: CompressionAlgorithm) -> io::Result<(SecureCookieEnvelopeMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_cookie_jar(jar);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure cookie nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_cookie_envelope_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureCookieEnvelopeMeta {
        algorithm: selected_algorithm,
        nonce_b64: pem::encode(&nonce),
        digest_b64: pem::encode(&digest),
        tag_b64: pem::encode(&tag),
        raw_size: raw_payload.len(),
        encoded_size: encoded_payload.len(),
        issued_at_unix,
        cookie_count: jar.len(),
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\ncookie-count={cookie_count}\n\n",
        magic = COOKIE_SECURE_ENVELOPE_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        nonce = meta.nonce_b64,
        digest = meta.digest_b64,
        tag = meta.tag_b64,
        raw_size = meta.raw_size,
        encoded_size = meta.encoded_size,
        issued_at = meta.issued_at_unix,
        cookie_count = meta.cookie_count,
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded_payload);

    Ok((meta, out))
}

pub fn encode_secure_cookie_jar_auto(jar: &CookieJar, accept_encoding: &str) -> io::Result<(SecureCookieEnvelopeMeta, Vec<u8>)> {
    let algorithm = select_secure_cookie_algorithm(accept_encoding);
    encode_secure_cookie_jar(jar, algorithm)
}

pub fn decode_secure_cookie_jar(secure_blob: &[u8]) -> io::Result<(SecureCookieEnvelopeMeta, CookieJar)> {
    let (header, body) = split_header_body(secure_blob)?;
    let meta = parse_secure_cookie_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nonce encoding in secure cookie envelope",
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest encoding in secure cookie envelope",
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tag encoding in secure cookie envelope",
        )
    })?;

    let computed_tag = compute_cookie_envelope_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope tag verification failed",
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
                "decoded payload size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded_payload.len()
            ),
        ));
    }

    let computed_digest = sha256(&decoded_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope digest verification failed",
        ));
    }

    let jar = deserialize_cookie_jar(&decoded_payload, meta.cookie_count)?;
    Ok((meta, jar))
}

pub fn new_cookie(name: impl Into<String>, value: impl Into<String>) -> Cookie {
    Cookie::new(name, value)
}

pub fn new_jar() -> CookieJar {
    CookieJar::new()
}

fn serialize_cookie_jar(jar: &CookieJar) -> Vec<u8> {
    let mut lines = Vec::new();
    for cookie in jar.all() {
        lines.push(cookie.to_string());
    }

    lines.join("\n").into_bytes()
}

fn deserialize_cookie_jar(raw_payload: &[u8], expected_count: usize) -> io::Result<CookieJar> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie payload is not valid UTF-8",
        )
    })?;

    let mut jar = CookieJar::new();
    let mut parsed_count = 0usize;
    for line in payload.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let cookie = parse_set_cookie(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse secure cookie entry: {}", e),
            )
        })?;

        jar.add(cookie);
        parsed_count += 1;
    }

    if parsed_count != expected_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cookie-count mismatch: expected {}, parsed {}",
                expected_count,
                parsed_count
            ),
        ));
    }

    Ok(jar)
}

fn compute_cookie_envelope_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(COOKIE_SECURE_ENVELOPE_CONTEXT.as_bytes());
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
            "secure cookie envelope header delimiter missing",
        )
    })?;

    let header_str = std::str::from_utf8(&data[..split_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope header is not utf-8",
        )
    })?.to_string();

    Ok((header_str, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_cookie_meta(header: &str, body_len: usize) -> io::Result<SecureCookieEnvelopeMeta> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope magic missing",
        )
    })?;

    if magic != COOKIE_SECURE_ENVELOPE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    let mut cookie_count = None::<usize>;
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
                if let Some(stripped) = value.strip_prefix("SHA-256=") {
                    digest_b64 = stripped.to_string();
                } else {
                    digest_b64 = value.to_string();
                }
            }
            "tag" => {
                if let Some(stripped) = value.strip_prefix("HMAC-SHA-256=") {
                    tag_b64 = stripped.to_string();
                } else {
                    tag_b64 = value.to_string();
                }
            }
            "raw-size" => {
                raw_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?)
            }
            "encoded-size" => {
                encoded_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?)
            }
            "issued-at" => {
                issued_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?)
            }
            "cookie-count" => {
                cookie_count = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid cookie-count")
                })?)
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope missing nonce, digest, or tag",
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope missing encoded-size",
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
            "secure cookie envelope missing issued-at",
        )
    })?;

    let cookie_count = cookie_count.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie envelope missing cookie-count",
        )
    })?;

    Ok(SecureCookieEnvelopeMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
        cookie_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cookie() {
        let cookie = new_cookie("test", "value");
        assert_eq!(cookie.name(), "test");
        assert_eq!(cookie.value(), "value");
    }

    #[test]
    fn test_create_jar() {
        let jar = new_jar();
        assert!(jar.is_empty());
    }

    #[test]
    fn test_parse_and_store() {
        let mut jar = new_jar();
        let cookie = parse_set_cookie("session=abc123; Path=/; Secure").unwrap();
        jar.add(cookie);

        assert_eq!(jar.len(), 1);
        let stored = jar.get("session").unwrap();
        assert_eq!(stored.value(), "abc123");
        assert!(stored.is_secure());
    }

    #[test]
    fn test_cookie_lifecycle() {
        let mut jar = new_jar();

        let cookie1 = parse_set_cookie("session=abc; Domain=example.com; Path=/").unwrap();
        let cookie2 = parse_set_cookie("token=xyz; Domain=example.com; Path=/api").unwrap();
        jar.add(cookie1);
        jar.add(cookie2);

        let matches = jar.get_matching("example.com", "/api/test", false);
        assert_eq!(matches.len(), 2);

        let header = jar.cookie_header("example.com", "/api", false).unwrap();
        assert!(header.contains("session=abc"));
        assert!(header.contains("token=xyz"));

        jar.remove("session");
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn test_same_site_attribute() {
        let cookie = parse_set_cookie("test=value; SameSite=Strict").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));

        let cookie = parse_set_cookie("test=value; SameSite=Lax").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));

        let cookie = parse_set_cookie("test=value; SameSite=None").unwrap();
        assert_eq!(cookie.same_site(), Some(SameSite::None));
    }

    #[test]
    fn test_secure_cookie_roundtrip_identity() {
        let mut jar = new_jar();
        jar.add(parse_set_cookie("session=abc123; Domain=example.com; Path=/; Secure").unwrap());
        jar.add(parse_set_cookie("token=xyz789; Domain=example.com; Path=/api; HttpOnly").unwrap());

        let (meta, blob) = encode_secure_cookie_jar(&jar, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.cookie_count, 2);

        let (decoded_meta, decoded_jar) = decode_secure_cookie_jar(&blob).unwrap();
        assert_eq!(decoded_meta.cookie_count, 2);
        assert_eq!(decoded_jar.len(), 2);
        assert!(decoded_jar.get("session").is_some());
        assert!(decoded_jar.get("token").is_some());
    }

    #[test]
    fn test_secure_cookie_roundtrip_compressed() {
        let mut jar = new_jar();
        jar.add(parse_set_cookie("a=1; Domain=example.com; Path=/").unwrap());
        jar.add(parse_set_cookie("b=2; Domain=example.com; Path=/").unwrap());
        jar.add(parse_set_cookie("c=3; Domain=example.com; Path=/").unwrap());

        let (meta, blob) = encode_secure_cookie_jar(&jar, CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.cookie_count, 3);

        let (decoded_meta, decoded_jar) = decode_secure_cookie_jar(&blob).unwrap();
        assert_eq!(decoded_meta.cookie_count, 3);
        assert_eq!(decoded_jar.len(), 3);
        assert!(decoded_jar.get("a").is_some());
        assert!(decoded_jar.get("b").is_some());
        assert!(decoded_jar.get("c").is_some());
    }

    #[test]
    fn test_secure_cookie_tamper_detected() {
        let mut jar = new_jar();
        jar.add(parse_set_cookie("session=abc123; Domain=example.com; Path=/").unwrap());

        let (_, mut blob) = encode_secure_cookie_jar(&jar, CompressionAlgorithm::Identity).unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_cookie_jar(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_select_secure_cookie_algorithm() {
        let selected = select_secure_cookie_algorithm("br, gzip;q=0.8, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let fallback = select_secure_cookie_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}