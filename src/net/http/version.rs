use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP_VERSION_BLOB_MAGIC: &str = "SINGULARITY_HTTP_VERSION_BLOB_V1";
const HTTP_VERSION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_VERSION_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpVersionBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "HTTP/1.0" => Some(HttpVersion::Http10),
            "HTTP/1.1" => Some(HttpVersion::Http11),
            "HTTP/2.0" | "HTTP/2" | "h2" => Some(HttpVersion::Http2),
            "HTTP/3.0" | "HTTP/3" | "h3" => Some(HttpVersion::Http3),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2.0",
            HttpVersion::Http3 => "HTTP/3.0",
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            HttpVersion::Http3 => 4,
            HttpVersion::Http2 => 3,
            HttpVersion::Http11 => 2,
            HttpVersion::Http10 => 1,
        }
    }

    pub fn alpn_protocol(&self) -> Option<&'static [u8]> {
        match self {
            HttpVersion::Http2 => Some(b"h2"),
            HttpVersion::Http3 => Some(b"h3"),
            HttpVersion::Http11 => Some(b"http/1.1"),
            HttpVersion::Http10 => None,
        }
    }

    pub fn negotiate(supported: &[HttpVersion], preferred: HttpVersion) -> HttpVersion {
        if supported.contains(&preferred) {
            return preferred;
        }

        supported.iter().max_by_key(|v| v.priority()).copied().unwrap_or(HttpVersion::Http11)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn uses_quic(&self) -> bool {
        matches!(self, HttpVersion::Http3)
    }

    pub fn requires_tls(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_server_push(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_keep_alive(&self) -> bool {
        matches!(self, HttpVersion::Http11 | HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_multiplexing(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_content_encoding(&self) -> bool {
        matches!(self, HttpVersion::Http11 | HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_accept_encoding(&self) -> bool {
        self.supports_content_encoding()
    }

    pub fn supports_digest_header(&self) -> bool {
        matches!(self, HttpVersion::Http11 | HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn default_accept_encoding(&self) -> &'static str {
        if self.supports_accept_encoding() {
            "br, zstd, gzip, deflate, identity"
        } else {
            "identity"
        }
    }

    pub fn parse_alt_svc(alt_svc: &str) -> Vec<(HttpVersion, String, u16)> {
        let mut versions = Vec::new();
        for entry in alt_svc.split(',') {
            let entry = entry.trim();
            if let Some((proto, rest)) = entry.split_once('=') {
                let proto = proto.trim().trim_matches('"');
                let version = match proto {
                    "h3" | "h3-29" => HttpVersion::Http3,
                    "h2" => HttpVersion::Http2,
                    "http/1.1" => HttpVersion::Http11,
                    _ => continue,
                };

                if let Some(host_port_raw) = rest.split(';').next() {
                    let host_port = host_port_raw.trim().trim_matches('"');
                    if let Some((host, port_str)) = host_port.rsplit_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            versions.push((version, host.to_string(), port));
                        }
                    }
                }
            }
        }

        versions
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

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpVersionBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_http_version(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure http-version nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_http_version_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let meta = SecureHttpVersionBlobMeta {
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
            magic = HTTP_VERSION_BLOB_MAGIC,
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

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpVersionBlobMeta, Vec<u8>)> {
        self.to_secure_blob(Self::select_secure_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttpVersionBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_http_version_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in secure http-version blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in secure http-version blob",
            )
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tag encoding in secure http-version blob",
            )
        })?;

        let computed_tag =
            compute_http_version_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure http-version blob tag verification failed",
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
                "secure http-version blob digest verification failed",
            ));
        }

        let version = deserialize_http_version(&decoded_payload)?;
        Ok((meta, version))
    }
}

fn serialize_http_version(version: &HttpVersion) -> Vec<u8> {
    let alpn = version.alpn_protocol().map(|v| String::from_utf8_lossy(v).to_string()).unwrap_or_default();
    format!(
        "version={version}\npriority={priority}\nis-binary={is_binary}\nuses-quic={uses_quic}\nrequires-tls={requires_tls}\nalpn={alpn}\n",
        version = version.as_str(),
        priority = version.priority(),
        is_binary = if version.is_binary() { "1" } else { "0" },
        uses_quic = if version.uses_quic() { "1" } else { "0" },
        requires_tls = if version.requires_tls() { "1" } else { "0" },
        alpn = alpn,
    ).into_bytes()
}

fn deserialize_http_version(raw_payload: &[u8]) -> io::Result<HttpVersion> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version payload is not valid utf-8",
        )
    })?;

    let mut map = std::collections::HashMap::new();
    for line in payload.lines() {
        let mut kv = line.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        if !key.is_empty() {
            map.insert(key.to_string(), value.to_string());
        }
    }

    let version_str = map.get("version").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version payload missing version",
        )
    })?;

    let version = HttpVersion::from_str(version_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported http version value: {}", version_str),
        )
    })?;

    if let Some(priority_str) = map.get("priority") {
        let parsed_priority = priority_str.parse::<u8>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid priority value")
        })?;

        if parsed_priority != version.priority() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-version payload priority mismatch",
            ));
        }
    }

    if let Some(v) = map.get("is-binary") {
        let parsed = parse_bool(v)?;
        if parsed != version.is_binary() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-version payload binary capability mismatch",
            ));
        }
    }

    if let Some(v) = map.get("uses-quic") {
        let parsed = parse_bool(v)?;
        if parsed != version.uses_quic() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-version payload quic capability mismatch",
            ));
        }
    }

    if let Some(v) = map.get("requires-tls") {
        let parsed = parse_bool(v)?;
        if parsed != version.requires_tls() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-version payload tls capability mismatch",
            ));
        }
    }

    if let Some(v) = map.get("alpn") {
        let expected = version.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string()).unwrap_or_default();
        if v != &expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-version payload alpn mismatch",
            ));
        }
    }

    Ok(version)
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

fn compute_http_version_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(HTTP_VERSION_BLOB_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    let hmac_key = sha256(&key_material);

    let mut msg = Vec::new();
    msg.extend_from_slice(HTTP_VERSION_BLOB_MAGIC.as_bytes());
    msg.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    msg.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &msg)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob header delimiter missing",
        )
    })?;

    let header = std::str::from_utf8(&data[..split_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob header is not utf-8",
        )
    })?.to_string();

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_http_version_meta(header: &str, body_len: usize) -> io::Result<SecureHttpVersionBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob magic missing",
        )
    })?;

    if magic != HTTP_VERSION_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob magic mismatch",
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
            "secure http-version blob missing nonce, digest, or tag",
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-version blob missing encoded-size",
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
            "secure http-version blob missing issued-at",
        )
    })?;

    Ok(SecureHttpVersionBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for HttpVersion {
    fn default() -> Self {
        HttpVersion::Http11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_version_from_str_variants() {
        assert_eq!(HttpVersion::from_str("HTTP/1.0"), Some(HttpVersion::Http10));
        assert_eq!(HttpVersion::from_str("HTTP/1.1"), Some(HttpVersion::Http11));
        assert_eq!(HttpVersion::from_str("HTTP/2"), Some(HttpVersion::Http2));
        assert_eq!(HttpVersion::from_str("h2"), Some(HttpVersion::Http2));
        assert_eq!(HttpVersion::from_str("HTTP/3"), Some(HttpVersion::Http3));
        assert_eq!(HttpVersion::from_str("h3"), Some(HttpVersion::Http3));
        assert_eq!(HttpVersion::from_str("HTTP/9.9"), None);
    }

    #[test]
    fn test_http_version_negotiate_prefers_highest_supported() {
        let supported = [HttpVersion::Http11, HttpVersion::Http2];
        assert_eq!(
            HttpVersion::negotiate(&supported, HttpVersion::Http3),
            HttpVersion::Http2
        );
    }

    #[test]
    fn test_secure_blob_roundtrip_identity() {
        let version = HttpVersion::Http2;
        let (meta, blob) = version
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure blob");

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_version) =
            HttpVersion::from_secure_blob(&blob).expect("failed to decode secure blob");

        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(decoded_version, version);
    }

    #[test]
    fn test_secure_blob_roundtrip_compressed() {
        let version = HttpVersion::Http3;
        let (_meta, blob) = version
            .to_secure_blob(CompressionAlgorithm::Gzip)
            .expect("failed to encode secure compressed blob");

        let (_decoded_meta, decoded_version) =
            HttpVersion::from_secure_blob(&blob).expect("failed to decode secure compressed blob");

        assert_eq!(decoded_version, version);
    }

    #[test]
    fn test_secure_blob_tamper_detected() {
        let version = HttpVersion::Http11;
        let (_meta, mut blob) = version
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure blob");

        let idx = blob
            .len()
            .checked_sub(1)
            .expect("blob should not be empty");
        blob[idx] ^= 0x01;

        let result = HttpVersion::from_secure_blob(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_alt_svc() {
        let parsed = HttpVersion::parse_alt_svc(r#"h3=":443"; ma=86400, h2="example.com:8443""#);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, HttpVersion::Http3);
        assert_eq!(parsed[1].0, HttpVersion::Http2);
        assert_eq!(parsed[1].1, "example.com");
        assert_eq!(parsed[1].2, 8443);
    }
}