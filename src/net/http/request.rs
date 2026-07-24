use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::http::headers::Headers;
use crate::net::http::method::HttpMethod;
use crate::net::http::version::HttpVersion;
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP_REQUEST_BLOB_MAGIC: &str = "SINGULARITY_HTTP_REQUEST_BLOB_V1";
const HTTP_REQUEST_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_REQUEST_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpRequestBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Clone)]
pub struct HttpRequest {
    method: HttpMethod,
    path: String,
    version: HttpVersion,
    headers: Headers,
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            version: HttpVersion::default(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn version_ref(&self) -> &HttpVersion {
        &self.version
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpRequestBlobMeta, Vec<u8>)> {
        encode_secure_http_request(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpRequestBlobMeta, Vec<u8>)> {
        encode_secure_http_request_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttpRequestBlobMeta, Self)> {
        decode_secure_http_request(data)
    }

    pub fn build(&self, host: &str) -> Vec<u8> {
        self.build_impl(host, true)
    }

    pub fn to_bytes(&self, host: &str) -> Vec<u8> {
        self.build(host)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let request_str = std::str::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {}", e))?;
        let header_end = request_str.find("\r\n\r\n")
            .ok_or_else(|| "No header terminator found".to_string())?;
        
        let header_section = &request_str[..header_end];
        let body_start = header_end + 4;
        let mut lines = header_section.lines();
        let request_line = lines.next().ok_or_else(|| "Empty request".to_string())?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(format!("Invalid request line: {}", request_line));
        }

        let method = HttpMethod::from_str(parts[0])
            .ok_or_else(|| format!("Invalid HTTP method: {}", parts[0]))?;

        let path = parts[1].to_string();
        let version = HttpVersion::from_str(parts[2])
            .ok_or_else(|| format!("Invalid HTTP version: {}", parts[2]))?;

        let mut headers = Headers::new();
        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.insert(name, value);
            } else {
                return Err(format!("Invalid header line: {}", line));
            }
        }

        let mut wire_body = if body_start < bytes.len() {
            bytes[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Self::verify_digest(&headers, &wire_body)?;
        if let Some(enc) = headers.get("content-encoding") {
            wire_body = Self::decode_content_encoding(enc, &wire_body)?;
        }

        Ok(Self {
            method,
            path,
            version,
            headers,
            body: wire_body,
        })
    }

    pub fn accept(&self) -> Option<&str> {
        self.headers.get("Accept")
    }

    pub fn accept_language(&self) -> Option<&str> {
        self.headers.get("Accept-Language")
    }

    pub fn accept_encoding(&self) -> Option<&str> {
        self.headers.get("Accept-Encoding")
    }

    pub fn accept_charset(&self) -> Option<&str> {
        self.headers.get("Accept-Charset")
    }

    pub fn set_accept(&mut self, media_types: Vec<String>) {
        self.headers.insert("Accept", media_types.join(", "));
    }

    pub fn set_accept_language(&mut self, languages: Vec<String>) {
        self.headers.insert("Accept-Language", languages.join(", "));
    }

    pub fn set_accept_encoding(&mut self, encodings: Vec<String>) {
        self.headers.insert("Accept-Encoding", encodings.join(", "));
    }

    pub fn set_accept_charset(&mut self, charsets: Vec<String>) {
        self.headers.insert("Accept-Charset", charsets.join(", "));
    }

    pub fn with_keep_alive(mut self) -> Self {
        self.headers.insert("Connection", "keep-alive");
        self
    }

    pub fn without_keep_alive(mut self) -> Self {
        self.headers.insert("Connection", "close");
        self
    }

    pub fn wants_keep_alive(&self) -> bool {
        self.headers.get("connection").map(|v| !v.to_lowercase().contains("close")).unwrap_or(true)
    }

    pub fn set_connection(&mut self, keep_alive: bool) {
        if keep_alive {
            self.headers.insert("Connection", "keep-alive");
        } else {
            self.headers.insert("Connection", "close");
        }
    }

    pub fn set_header<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.headers.insert(key.into(), value.into());
    }

    pub fn set_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        if !self.body.is_empty() {
            self.headers.insert("Content-Length", self.body.len().to_string());
        }

        self
    }

    pub fn build_with_defaults(&self, host: &str) -> Vec<u8> {
        self.build_impl(host, true)
    }

    fn build_impl(&self, host: &str, include_defaults: bool) -> Vec<u8> {
        let mut request = String::new();
        request.push_str(&format!(
            "{} {} {}\r\n",
            self.method.as_str(),
            self.path,
            self.version.as_str()
        ));

        let mut headers = self.headers.clone();
        if include_defaults {
            if !headers.contains("Host") {
                headers.insert("Host", host);
            }

            if !headers.contains("User-Agent") {
                headers.insert("User-Agent", "Singularity/0.0.1");
            }

            if !headers.contains("Accept") {
                headers.insert("Accept", "*/*");
            }

            if !headers.contains("Accept-Encoding") {
                headers.insert("Accept-Encoding", "br, zstd, gzip, deflate, identity");
            }

            if !headers.contains("Connection") {
                headers.insert("Connection", "keep-alive");
            }
        }

        let wire_body = self.encode_content_encoding(headers.get("content-encoding")).unwrap_or_else(|_| self.body.clone());
        if !wire_body.is_empty() && !headers.contains("Content-Length") {
            headers.insert("Content-Length", wire_body.len().to_string());
        } else if !wire_body.is_empty() {
            headers.insert("Content-Length", wire_body.len().to_string());
        }

        if !wire_body.is_empty() && !headers.contains("Digest") {
            let digest_b64 = pem::encode(&sha256(&wire_body));
            headers.insert("Digest", format!("SHA-256={}", digest_b64));
            headers.insert("X-Content-SHA256", Self::to_hex(&sha256(&wire_body)));
        }

        request.push_str(&headers.format());
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&wire_body);

        bytes
    }

    fn encode_content_encoding(&self, content_encoding: Option<&str>) -> Result<Vec<u8>, String> {
        let Some(enc) = content_encoding else {
            return Ok(self.body.clone());
        };

        let encoding = enc.trim().to_ascii_lowercase();
        if encoding.is_empty() || encoding == "identity" {
            return Ok(self.body.clone());
        }

        let algo = CompressionAlgorithm::from_content_encoding(&encoding)
            .ok_or_else(|| format!("Unsupported content-encoding: {}", enc))?;

        compression::compress(algo, &self.body, compression::CompressionLevel::Default)
            .map_err(|e| format!("Failed to encode request body: {}", e))
    }

    fn decode_content_encoding(content_encoding: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let encoding = content_encoding.trim().to_ascii_lowercase();
        if encoding.is_empty() || encoding == "identity" {
            return Ok(body.to_vec());
        }

        let algo = CompressionAlgorithm::from_content_encoding(&encoding)
            .ok_or_else(|| format!("Unsupported content-encoding: {}", content_encoding))?;

        compression::decompress(algo, body).map_err(|e| format!("Failed to decode request body: {}", e))
    }

    fn verify_digest(headers: &Headers, wire_body: &[u8]) -> Result<(), String> {
        let Some(digest_header) = headers.get("digest") else {
            return Ok(());
        };

        let mut has_sha256 = false;
        let mut matched = false;
        for part in digest_header.split(',') {
            let p = part.trim();
            let mut kv = p.splitn(2, '=');
            let algo = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = kv.next().unwrap_or("").trim();
            if algo == "sha-256" {
                has_sha256 = true;
                let expected =
                    pem::decode(value).map_err(|e| format!("Invalid digest encoding: {}", e))?;
                let actual = sha256(wire_body);
                if constant_time_eq(&expected, &actual) {
                    matched = true;
                }
            }
        }

        if has_sha256 && !matched {
            return Err("Digest verification failed".to_string());
        }

        Ok(())
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }

        out
    }
}

pub fn select_secure_http_request_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http_request(request: &HttpRequest, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpRequestBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http_request(request);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate request blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http_request_blob_tag(
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
        magic = HTTP_REQUEST_BLOB_MAGIC,
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
        SecureHttpRequestBlobMeta {
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

pub fn encode_secure_http_request_auto(request: &HttpRequest, accept_encoding: &str) -> io::Result<(SecureHttpRequestBlobMeta, Vec<u8>)> {
    let selected = select_secure_http_request_algorithm(accept_encoding);
    encode_secure_http_request(request, selected)
}

pub fn decode_secure_http_request(data: &[u8]) -> io::Result<(SecureHttpRequestBlobMeta, HttpRequest)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http_request_meta(&header, body.len())?;
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

    let expected_tag = compute_http_request_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http-request blob HMAC mismatch",
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
            "http-request blob digest mismatch",
        ));
    }

    let request = deserialize_http_request(&raw_payload)?;
    Ok((meta, request))
}

fn serialize_http_request(request: &HttpRequest) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!("method={}", request.method.as_str()));
    lines.push(format!("path={}", pem::encode(request.path.as_bytes())));
    lines.push(format!("version={}", request.version.as_str()));
    let mut headers_sorted: Vec<(&String, &Vec<String>)> = request.headers.iter().collect();
    headers_sorted.sort_by(|(ka, _), (kb, _)| ka.cmp(kb));
    for (name, values) in headers_sorted {
        for value in values {
            lines.push(format!(
                "h={}|{}",
                pem::encode(name.as_bytes()),
                pem::encode(value.as_bytes())
            ));
        }
    }

    lines.push(format!("body={}", pem::encode(&request.body)));
    lines.join("\n").into_bytes()
}

fn deserialize_http_request(raw_payload: &[u8]) -> io::Result<HttpRequest> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "http-request payload is not valid UTF-8",
        )
    })?;

    let mut method = None;
    let mut path = None::<String>;
    let mut version = None;
    let mut headers = Headers::new();
    let mut body = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("method=") {
            method = HttpMethod::from_str(v.trim());
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("path=") {
            let decoded = pem::decode(v.trim()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid path encoding: {}", e))
            })?;

            let decoded = String::from_utf8(decoded).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "path is not valid UTF-8")
            })?;

            path = Some(decoded);
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("version=") {
            version = HttpVersion::from_str(v.trim());
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("h=") {
            let (name_b64, value_b64) = v.split_once('|').ok_or_else(|| {
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
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("body=") {
            body = pem::decode(v.trim()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid body encoding: {}", e))
            })?;

            continue;
        }
    }

    let method = method.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing method in request payload")
    })?;

    let path = path.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing path in request payload")
    })?;

    let version = version.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing version in request payload")
    })?;

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

fn compute_http_request_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP_REQUEST_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP_REQUEST_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http_request_meta(header: &str, body_len: usize) -> io::Result<SecureHttpRequestBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_REQUEST_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-request blob magic mismatch",
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
                format!("invalid secure request header line '{}'", line),
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
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure request blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure request blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure request blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure request blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing encoded-size in secure request blob")
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
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in secure request blob")
    })?;

    Ok(SecureHttpRequestBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body_length", &self.body.len())
            .finish()
    }
}

pub struct RequestBuilder {
    request: HttpRequest,
}

impl RequestBuilder {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            request: HttpRequest::new(method, path),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request = self.request.body(body);
        self
    }

    pub fn build(self) -> HttpRequest {
        self.request
    }

    pub fn keep_alive(mut self, enable: bool) -> Self {
        if enable {
            self.request.headers_mut().insert("Connection", "keep-alive");
        } else {
            self.request.headers_mut().insert("Connection", "close");
        }

        self
    }

    pub fn connection(mut self, connection_type: impl Into<String>) -> Self {
        self.request
            .headers_mut()
            .insert("Connection", connection_type);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_request_blob_roundtrip_identity() {
        let request = HttpRequest::new(HttpMethod::POST, "/api/v1/items")
            .version(HttpVersion::Http11)
            .header("Content-Type", "application/json")
            .header("X-Test", "true")
            .body(br#"{"id":1}"#.to_vec());

        let (meta, blob) = request
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = HttpRequest::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.method(), HttpMethod::POST);
        assert_eq!(restored.path(), "/api/v1/items");
        assert_eq!(restored.version_ref(), &HttpVersion::Http11);
        assert_eq!(restored.headers().get("content-type"), Some("application/json"));
        assert_eq!(restored.headers().get("x-test"), Some("true"));
        assert_eq!(restored.body_bytes(), br#"{"id":1}"#);
    }

    #[test]
    fn test_secure_request_blob_tamper_detection() {
        let request = HttpRequest::new(HttpMethod::GET, "/health");

        let (_, mut blob) = request
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = HttpRequest::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}