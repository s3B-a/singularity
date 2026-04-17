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

const COOKIE_BLOB_MAGIC: &str = "SINGULARITY_COOKIE_BLOB_V1";
const COOKIE_BLOB_CONTEXT: &str = "SINGULARITY_COOKIE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCookieBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    expires: Option<u64>,
    max_age: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn set_domain(&mut self, domain: impl Into<String>) {
        self.domain = Some(domain.into());
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn set_path(&mut self, path: Option<String>) {
        self.path = path;
    }

    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    pub fn set_expires(&mut self, expires: Option<u64>) {
        self.expires = expires;
    }

    pub fn max_age(&self) -> Option<i64> {
        self.max_age
    }

    pub fn set_max_age(&mut self, max_age: Option<i64>) {
        self.max_age = max_age;
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    pub fn is_http_only(&self) -> bool {
        self.http_only
    }

    pub fn set_http_only(&mut self, http_only: bool) {
        self.http_only = http_only;
    }

    pub fn same_site(&self) -> Option<SameSite> {
        self.same_site.clone()
    }

    pub fn set_same_site(&mut self, same_site: Option<SameSite>) {
        self.same_site = same_site;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            return now >= expires;
        }

        if let Some(max_age) = self.max_age {
            return max_age <= 0;
        }

        false
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        match &self.domain {
            Some(cookie_domain) => {
                domain == cookie_domain || domain.ends_with(&format!(".{}", cookie_domain))
            }
            None => true,
        }
    }

    pub fn matches_path(&self, path: &str) -> bool {
        match &self.path {
            Some(cookie_path) => path.starts_with(cookie_path),
            None => true,
        }
    }

    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    pub fn select_secure_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
        let accepted = compression::parse_accept_encoding(accept_encoding);
        for (algorithm, quality) in accepted {
            if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
                return algorithm;
            }
        }

        CompressionAlgorithm::Identity
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureCookieBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_cookie(self);
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
        let tag = compute_cookie_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let meta = SecureCookieBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix,
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = COOKIE_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix,
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded_payload);

        Ok((meta, out))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureCookieBlobMeta, Vec<u8>)> {
        let algorithm = Self::select_secure_algorithm(accept_encoding);
        self.to_secure_blob(algorithm)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureCookieBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_cookie_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in secure cookie blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in secure cookie blob",
            )
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tag encoding in secure cookie blob",
            )
        })?;

        let computed_tag = compute_cookie_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure cookie blob tag verification failed",
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
                "secure cookie blob digest verification failed",
            ));
        }

        let cookie = deserialize_cookie(&decoded_payload)?;
        Ok((meta, cookie))
    }
}

fn serialize_cookie(cookie: &Cookie) -> Vec<u8> {
    let domain_b64 = cookie.domain.as_ref().map(|v| pem::encode(v.as_bytes())).unwrap_or_default();
    let path_b64 = cookie.path.as_ref().map(|v| pem::encode(v.as_bytes())).unwrap_or_default();
    let same_site = match cookie.same_site {
        Some(SameSite::Strict) => "Strict",
        Some(SameSite::Lax) => "Lax",
        Some(SameSite::None) => "None",
        None => "",
    };

    let payload = format!(
        "name={name}\nvalue={value}\ndomain={domain}\npath={path}\nexpires={expires}\nmax-age={max_age}\nsecure={secure}\nhttp-only={http_only}\nsame-site={same_site}\n",
        name = pem::encode(cookie.name.as_bytes()),
        value = pem::encode(cookie.value.as_bytes()),
        domain = domain_b64,
        path = path_b64,
        expires = cookie.expires.map(|v| v.to_string()).unwrap_or_default(),
        max_age = cookie.max_age.map(|v| v.to_string()).unwrap_or_default(),
        secure = if cookie.secure { "1" } else { "0" },
        http_only = if cookie.http_only { "1" } else { "0" },
        same_site = same_site,
    );

    payload.into_bytes()
}

fn deserialize_cookie(raw_payload: &[u8]) -> io::Result<Cookie> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie payload is not valid utf-8",
        )
    })?;

    let mut values = HashMap::new();
    for line in payload.lines() {
        let mut kv = line.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        if !key.is_empty() {
            values.insert(key.to_string(), value.to_string());
        }
    }

    let name_b64 = values.get("name").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure cookie payload missing name")
    })?;

    let value_b64 = values.get("value").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure cookie payload missing value")
    })?;

    let name_bytes = pem::decode(name_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 for cookie name")
    })?;

    let value_bytes = pem::decode(value_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 for cookie value")
    })?;

    let name = String::from_utf8(name_bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "cookie name is not valid utf-8")
    })?;

    let value = String::from_utf8(value_bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "cookie value is not valid utf-8")
    })?;

    let mut cookie = Cookie::new(name, value);
    if let Some(domain_b64) = values.get("domain") {
        if !domain_b64.is_empty() {
            let domain_bytes = pem::decode(domain_b64).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid base64 for cookie domain")
            })?;
            let domain = String::from_utf8(domain_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "cookie domain is not valid utf-8")
            })?;
            cookie.set_domain(domain);
        }
    }

    if let Some(path_b64) = values.get("path") {
        if !path_b64.is_empty() {
            let path_bytes = pem::decode(path_b64).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid base64 for cookie path")
            })?;
            let path = String::from_utf8(path_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "cookie path is not valid utf-8")
            })?;
            cookie.set_path(Some(path));
        }
    }

    if let Some(expires_str) = values.get("expires") {
        if !expires_str.is_empty() {
            let expires = expires_str.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid cookie expires value")
            })?;
            cookie.set_expires(Some(expires));
        }
    }

    if let Some(max_age_str) = values.get("max-age") {
        if !max_age_str.is_empty() {
            let max_age = max_age_str.parse::<i64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid cookie max-age value")
            })?;
            cookie.set_max_age(Some(max_age));
        }
    }

    if let Some(secure_str) = values.get("secure") {
        cookie.set_secure(parse_bool(secure_str)?);
    }

    if let Some(http_only_str) = values.get("http-only") {
        cookie.set_http_only(parse_bool(http_only_str)?);
    }

    if let Some(same_site_str) = values.get("same-site") {
        let same_site = match same_site_str.as_str() {
            "Strict" => Some(SameSite::Strict),
            "Lax" => Some(SameSite::Lax),
            "None" => Some(SameSite::None),
            "" => None,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid same-site value in secure cookie payload",
                ))
            }
        };
        cookie.set_same_site(same_site);
    }

    Ok(cookie)
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v {
        "1" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value: {}", v),
        )),
    }
}

fn compute_cookie_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(COOKIE_BLOB_CONTEXT.as_bytes());
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
            "secure cookie blob header delimiter missing",
        )
    })?;

    let header = std::str::from_utf8(&data[..split_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie blob header is not utf-8",
        )
    })?.to_string();

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_cookie_meta(header: &str, body_len: usize) -> io::Result<SecureCookieBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure cookie blob magic missing")
    })?;

    if magic != COOKIE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie blob magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
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
            "issued-at" => {
                issued_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie blob missing nonce, digest, or tag",
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure cookie blob missing raw-size")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure cookie blob missing encoded-size",
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
            "secure cookie blob missing issued-at",
        )
    })?;

    Ok(SecureCookieBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;
        if let Some(domain) = &self.domain {
            write!(f, "; Domain={}", domain)?;
        }

        if let Some(path) = &self.path {
            write!(f, "; Path={}", path)?;
        }

        if let Some(expires) = self.expires {
            write!(f, "; Expires={}", expires)?;
        }

        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={}", max_age)?;
        }

        if self.secure {
            write!(f, "; Secure")?;
        }

        if self.http_only {
            write!(f, "; HttpOnly")?;
        }

        if let Some(same_site) = self.same_site.clone() {
            write!(f, "; SameSite={}", same_site)?;
        }

        Ok(())
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_basic_properties() {
        let mut cookie = Cookie::new("session", "abc123");
        cookie.set_domain("example.com");
        cookie.set_path(Some("/api".to_string()));
        cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc123");
        assert_eq!(cookie.domain(), Some("example.com"));
        assert_eq!(cookie.path(), Some("/api"));
        assert!(cookie.is_secure());
        assert!(cookie.is_http_only());
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn test_secure_cookie_roundtrip_identity() {
        let mut cookie = Cookie::new("session", "abc123");
        cookie.set_domain("example.com");
        cookie.set_path(Some("/".to_string()));
        cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Strict));
        cookie.set_max_age(Some(3600));

        let (meta, blob) = cookie.to_secure_blob(CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_cookie) = Cookie::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(decoded_cookie.name(), "session");
        assert_eq!(decoded_cookie.value(), "abc123");
        assert_eq!(decoded_cookie.domain(), Some("example.com"));
        assert_eq!(decoded_cookie.path(), Some("/"));
        assert!(decoded_cookie.is_secure());
        assert!(decoded_cookie.is_http_only());
        assert_eq!(decoded_cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(decoded_cookie.max_age(), Some(3600));
    }

    #[test]
    fn test_secure_cookie_roundtrip_compressed() {
        let mut cookie = Cookie::new(
            "long-cookie-name",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        );
        cookie.set_domain("example.com");
        cookie.set_path(Some("/very/long/path".to_string()));

        let (meta, blob) = cookie.to_secure_blob(CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (_, decoded_cookie) = Cookie::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_cookie.name(), cookie.name());
        assert_eq!(decoded_cookie.value(), cookie.value());
        assert_eq!(decoded_cookie.domain(), cookie.domain());
        assert_eq!(decoded_cookie.path(), cookie.path());
    }

    #[test]
    fn test_secure_cookie_tamper_detected() {
        let cookie = Cookie::new("session", "abc123");
        let (_, mut blob) = cookie.to_secure_blob(CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = Cookie::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_select_secure_algorithm() {
        let selected = Cookie::select_secure_algorithm("br, gzip;q=0.8, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let fallback = Cookie::select_secure_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}