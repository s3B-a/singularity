use super::cookie::Cookie;
use super::parser::parse_set_cookie;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const COOKIE_JAR_SNAPSHOT_MAGIC: &str = "SINGULARITY_COOKIE_JAR_SNAPSHOT_V2";
const COOKIE_JAR_SNAPSHOT_CONTEXT: &str = "SINGULARITY_COOKIE_JAR_SNAPSHOT_BINDING_V2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieJarSnapshotMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub issued_at_unix: u64,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub cookie_count: usize,
}

#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    pub fn add(&mut self, cookie: Cookie) {
        let key = self.make_key(&cookie);
        self.cookies.insert(key, cookie);
    }

    pub fn get(&self, name: &str) -> Option<&Cookie> {
        self.cookies.values().find(|c| c.name() == name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Cookie> {
        self.cookies.values_mut().find(|c| c.name() == name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Cookie> {
        let key = self.cookies.iter().find(|(_, c)| c.name() == name).map(|(k, _)| k.clone())?;
        self.cookies.remove(&key)
    }

    pub fn get_matching(&self, domain: &str, path: &str, secure: bool) -> Vec<&Cookie> {
        self.cookies.values().filter(|cookie| {
            !cookie.is_expired()
                && cookie.matches_domain(domain)
                && cookie.matches_path(path)
                && (!cookie.is_secure() || secure)
        }).collect()
    }

    pub fn all(&self) -> Vec<&Cookie> {
        self.cookies.values().collect()
    }

    pub fn remove_expired(&mut self) {
        self.cookies.retain(|_, cookie| !cookie.is_expired());
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    pub fn cookie_header(&self, domain: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.get_matching(domain, path, secure);
        if cookies.is_empty() {
            return None;
        }

        let header = cookies.iter().map(|c| c.to_header_value()).collect::<Vec<_>>().join("; ");

        Some(header)
    }

    pub fn export_secure_snapshot(&self, algorithm: CompressionAlgorithm) -> io::Result<(CookieJarSnapshotMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = self.serialize_snapshot_payload();
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate cookie jar snapshot nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_snapshot_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let meta = CookieJarSnapshotMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            issued_at_unix,
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            cookie_count: self.len(),
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nissued-at={issued_at}\nraw-size={raw_size}\nencoded-size={encoded_size}\ncookie-count={cookie_count}\n\n",
            magic = COOKIE_JAR_SNAPSHOT_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            issued_at = meta.issued_at_unix,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            cookie_count = meta.cookie_count,
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded_payload);

        Ok((meta, out))
    }

    pub fn export_secure_snapshot_auto(&self, accept_encoding: &str) -> io::Result<(CookieJarSnapshotMeta, Vec<u8>)> {
        let algorithm = Self::select_secure_snapshot_algorithm(accept_encoding);
        self.export_secure_snapshot(algorithm)
    }

    pub fn import_secure_snapshot(data: &[u8]) -> io::Result<(CookieJarSnapshotMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_snapshot_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in cookie jar snapshot",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in cookie jar snapshot",
            )
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tag encoding in cookie jar snapshot",
            )
        })?;

        let computed_tag = compute_snapshot_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cookie jar snapshot tag verification failed",
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
                    "cookie jar snapshot raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    decoded_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&decoded_payload);
        if !constant_time_eq(&expected_digest, &computed_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cookie jar snapshot digest verification failed",
            ));
        }

        let jar = Self::deserialize_snapshot_payload(&decoded_payload, meta.cookie_count)?;
        Ok((meta, jar))
    }

    pub fn merge_secure_snapshot(&mut self, data: &[u8]) -> io::Result<CookieJarSnapshotMeta> {
        let (meta, snapshot) = Self::import_secure_snapshot(data)?;
        self.merge(&snapshot);
        Ok(meta)
    }

    pub fn select_secure_snapshot_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
        let accepted = compression::parse_accept_encoding(accept_encoding);
        for (algorithm, quality) in accepted {
            if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
                return algorithm;
            }
        }

        CompressionAlgorithm::Identity
    }

    fn make_key(&self, cookie: &Cookie) -> String {
        format!("{};{};{}", cookie.name(), cookie.domain().unwrap_or(""), cookie.path().unwrap_or("/"))
    }

    pub fn merge(&mut self, other: &CookieJar) {
        for cookie in other.all() {
            self.add(cookie.clone());
        }
    }

    pub fn cookies_for_domain(&self, domain: &str) -> Vec<&Cookie> {
        self.cookies.values().filter(|cookie| cookie.matches_domain(domain)).collect()
    }

    pub fn set(&mut self, cookie: Cookie) {
        self.add(cookie);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn names(&self) -> Vec<String> {
        self.cookies.values().map(|c| c.name().to_string()).collect()
    }

    fn serialize_snapshot_payload(&self) -> Vec<u8> {
        let mut entries: Vec<(&String, &Cookie)> = self.cookies.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut lines = Vec::with_capacity(entries.len());
        for (_, cookie) in entries {
            lines.push(cookie.to_string());
        }

        lines.join("\n").into_bytes()
    }

    fn deserialize_snapshot_payload(raw_payload: &[u8], expected_count: usize) -> io::Result<CookieJar> {
        let payload = std::str::from_utf8(raw_payload).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cookie jar snapshot payload is not valid utf-8",
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
                    format!("failed to parse cookie snapshot line: {}", e),
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
                    expected_count, parsed_count
                ),
            ));
        }

        Ok(jar)
    }
}

fn compute_snapshot_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(COOKIE_JAR_SNAPSHOT_CONTEXT.as_bytes());
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
            "cookie jar snapshot header delimiter missing",
        )
    })?;

    let header = std::str::from_utf8(&data[..split_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot header is not utf-8",
        )
    })?.to_string();

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_snapshot_meta(header: &str, body_len: usize) -> io::Result<CookieJarSnapshotMeta> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot magic missing",
        )
    })?;

    if magic != COOKIE_JAR_SNAPSHOT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut issued_at_unix = None::<u64>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
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
            "cookie-count" => {
                cookie_count = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid cookie-count")
                })?);
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot missing nonce, digest, or tag",
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot missing issued-at",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot missing encoded-size",
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

    let cookie_count = cookie_count.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie jar snapshot missing cookie-count",
        )
    })?;

    Ok(CookieJarSnapshotMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        issued_at_unix,
        raw_size,
        encoded_size,
        cookie_count,
    })
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<Cookie> for CookieJar {
    fn from_iter<T: IntoIterator<Item = Cookie>>(iter: T) -> Self {
        let mut jar = CookieJar::new();
        for cookie in iter {
            jar.add(cookie);
        }
        jar
    }
}

impl Extend<Cookie> for CookieJar {
    fn extend<T: IntoIterator<Item = Cookie>>(&mut self, iter: T) {
        for cookie in iter {
            self.add(cookie);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_cookie() {
        let mut jar = CookieJar::new();
        let cookie = Cookie::new("session", "abc123");
        jar.add(cookie);

        assert_eq!(jar.len(), 1);
        assert!(jar.contains("session"));
        assert_eq!(jar.get("session").unwrap().value(), "abc123");
    }

    #[test]
    fn test_remove_cookie() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("session", "abc123"));

        let removed = jar.remove("session");
        assert!(removed.is_some());
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn test_cookie_matching() {
        let mut jar = CookieJar::new();
        let mut cookie = Cookie::new("test", "value");
        cookie.set_domain("example.com".to_string());
        cookie.set_path(Some("/api".to_string()));
        jar.add(cookie);

        let matches = jar.get_matching("example.com", "/api/v1", false);
        assert_eq!(matches.len(), 1);

        let no_matches = jar.get_matching("other.com", "/api/v1", false);
        assert_eq!(no_matches.len(), 0);
    }

    #[test]
    fn test_cookie_header() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("session", "abc123"));
        jar.add(Cookie::new("token", "xyz789"));

        let header = jar.cookie_header("example.com", "/", false).unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("token=xyz789"));
    }

    #[test]
    fn test_secure_snapshot_roundtrip_identity() {
        let mut jar = CookieJar::new();
        jar.add(parse_set_cookie("session=abc123; Domain=example.com; Path=/; Secure").unwrap());
        jar.add(parse_set_cookie("token=xyz789; Domain=example.com; Path=/api; HttpOnly").unwrap());

        let (meta, blob) = jar
            .export_secure_snapshot(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.cookie_count, 2);

        let (decoded_meta, decoded_jar) = CookieJar::import_secure_snapshot(&blob).unwrap();
        assert_eq!(decoded_meta.cookie_count, 2);
        assert_eq!(decoded_jar.len(), 2);
        assert!(decoded_jar.get("session").is_some());
        assert!(decoded_jar.get("token").is_some());
    }

    #[test]
    fn test_secure_snapshot_roundtrip_compressed() {
        let mut jar = CookieJar::new();
        jar.add(parse_set_cookie("a=1; Domain=example.com; Path=/").unwrap());
        jar.add(parse_set_cookie("b=2; Domain=example.com; Path=/").unwrap());
        jar.add(parse_set_cookie("c=3; Domain=example.com; Path=/").unwrap());

        let (meta, blob) = jar
            .export_secure_snapshot(CompressionAlgorithm::Gzip)
            .unwrap();
        assert_eq!(meta.cookie_count, 3);

        let (decoded_meta, decoded_jar) = CookieJar::import_secure_snapshot(&blob).unwrap();
        assert_eq!(decoded_meta.cookie_count, 3);
        assert_eq!(decoded_jar.len(), 3);
        assert!(decoded_jar.get("a").is_some());
        assert!(decoded_jar.get("b").is_some());
        assert!(decoded_jar.get("c").is_some());
    }

    #[test]
    fn test_secure_snapshot_tamper_detected() {
        let mut jar = CookieJar::new();
        jar.add(parse_set_cookie("session=abc123; Domain=example.com; Path=/").unwrap());

        let (_, mut blob) = jar
            .export_secure_snapshot(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = CookieJar::import_secure_snapshot(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_secure_snapshot_merge() {
        let mut left = CookieJar::new();
        left.add(parse_set_cookie("session=left; Domain=example.com; Path=/").unwrap());

        let mut right = CookieJar::new();
        right.add(parse_set_cookie("token=right; Domain=example.com; Path=/").unwrap());

        let (_, blob) = right
            .export_secure_snapshot(CompressionAlgorithm::Identity)
            .unwrap();
        let meta = left.merge_secure_snapshot(&blob).unwrap();

        assert_eq!(meta.cookie_count, 1);
        assert!(left.get("session").is_some());
        assert!(left.get("token").is_some());
    }

    #[test]
    fn test_select_secure_snapshot_algorithm() {
        let selected =
            CookieJar::select_secure_snapshot_algorithm("br, gzip;q=0.8, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let fallback = CookieJar::select_secure_snapshot_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}