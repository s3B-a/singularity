use super::compression::{self, CompressionAlgorithm, CompressionLevel};
use super::version::HttpVersion;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP_RESPONSE_BLOB_MAGIC: &str = "SINGULARITY_HTTP_RESPONSE_BLOB_V1";
const HTTP_RESPONSE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_RESPONSE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpResponseBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub struct HttpResponse {
    status_code: u16,
    reason_phrase: String,
    version: HttpVersion,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(
        status_code: u16,
        reason_phrase: String,
        version: HttpVersion,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status_code,
            reason_phrase,
            version,
            headers,
            body,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn reason_phrase(&self) -> &str {
        &self.reason_phrase
    }

    pub fn version(&self) -> HttpVersion {
        self.version
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    pub fn header(&self, key: &str) -> Option<&String> {
        Self::get_header_case_insensitive(&self.headers, key)
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpResponseBlobMeta, Vec<u8>)> {
        encode_secure_http_response(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpResponseBlobMeta, Vec<u8>)> {
        encode_secure_http_response_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttpResponseBlobMeta, Self)> {
        decode_secure_http_response(data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = String::new();
        response.push_str(&format!(
            "{} {} {}\r\n",
            self.version.as_str(),
            self.status_code,
            self.reason_phrase
        ));

        for (key, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }

        if !self.body.is_empty() && Self::get_header_case_insensitive(&self.headers, "content-length").is_none() {
            response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }

        response.push_str("\r\n");
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let header_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "No header terminator found".to_string())?;

        let header_section = &bytes[..header_end];
        let body_start = header_end + 4;
        let header_str = std::str::from_utf8(header_section)
            .map_err(|e| format!("Invalid UTF-8 in headers: {}", e))?;

        let mut lines = header_str.lines();
        let status_line = lines.next().ok_or_else(|| "Empty response".to_string())?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid status line: {}", status_line));
        }

        let version = HttpVersion::from_str(parts[0])
            .ok_or_else(|| format!("Invalid HTTP version: {}", parts[0]))?;

        let status_code = parts[1].parse::<u16>()
            .map_err(|_| format!("Invalid status code: {}", parts[1]))?;
        
        let reason_phrase = if parts.len() == 3 {
            parts[2].to_string()
        } else {
            Self::default_reason_phrase(status_code)
        };

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            } else {
                return Err(format!("Invalid header line: {}", line));
            }
        }

        let wire_body = if body_start < bytes.len() {
            if let Some(content_length_str) = Self::get_header_case_insensitive(&headers, "content-length") {
                let content_length = content_length_str.parse::<usize>()
                    .map_err(|_| format!("Invalid Content-Length: {}", content_length_str))?;

                let body_end = body_start + content_length;
                if body_end > bytes.len() {
                    return Err(format!(
                        "Content-Length ({}) exceeds available data ({})",
                        content_length,
                        bytes.len() - body_start
                    ));
                }

                bytes[body_start..body_end].to_vec()
            } else if Self::get_header_case_insensitive(&headers, "transfer-encoding").map(|s| s.eq_ignore_ascii_case("chunked")).unwrap_or(false) {
                Self::decode_chunked(&bytes[body_start..])?
            } else {
                bytes[body_start..].to_vec()
            }
        } else {
            Vec::new()
        };

        Self::verify_digest_header(&headers, &wire_body)?;
        let mut final_body = wire_body;
        if let Some(content_encoding) = Self::get_header_case_insensitive(&headers, "content-encoding").cloned() {
            final_body = Self::decode_content_encoding(&content_encoding, &final_body)?;
            headers.remove("content-encoding");
            headers.insert("Content-Length".to_string(), final_body.len().to_string());
        }

        Ok(Self {
            status_code,
            reason_phrase,
            version,
            headers,
            body: final_body,
        })
    }

    fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let mut pos = 0;
        loop {
            let size_line_end = data[pos..].windows(2).position(|w| w == b"\r\n")
                .ok_or_else(|| "Malformed chunked encoding: no CRLF after chunk size".to_string())?;

            let size_str = std::str::from_utf8(&data[pos..pos + size_line_end])
                .map_err(|_| "Invalid UTF-8 in chunk size".to_string())?;

            let size_part = size_str.split(';').next().unwrap_or(size_str).trim();
            let chunk_size = usize::from_str_radix(size_part, 16)
                .map_err(|_| format!("Invalid chunk size: {}", size_part))?;

            pos += size_line_end + 2;
            if chunk_size == 0 {
                break;
            }

            if pos + chunk_size > data.len() {
                return Err("Chunk size exceeds available data".to_string());
            }

            result.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size;
            if pos + 2 > data.len() || &data[pos..pos + 2] != b"\r\n" {
                return Err("Missing CRLF after chunk data".to_string());
            }

            pos += 2;
        }

        Ok(result)
    }

    fn decode_content_encoding(content_encoding: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let encoding = content_encoding.trim().to_ascii_lowercase();
        if encoding.is_empty() || encoding == "identity" {
            return Ok(body.to_vec());
        }

        let algo = CompressionAlgorithm::from_content_encoding(&encoding)
            .ok_or_else(|| format!("Unsupported content-encoding: {}", content_encoding))?;

        compression::decompress(algo, body).map_err(|e| format!("Failed to decode body: {}", e))
    }

    fn verify_digest_header(headers: &HashMap<String, String>, wire_body: &[u8]) -> Result<(), String> {
        let Some(digest_header) = Self::get_header_case_insensitive(headers, "digest") else {
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
                let expected = pem::decode(value)
                    .map_err(|e| format!("Invalid digest encoding: {}", e))?;

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

    fn get_header_case_insensitive<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }

    pub fn default_reason_phrase(status_code: u16) -> String {
        match status_code {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
        .to_string()
    }

    pub fn wants_keep_alive(&self) -> bool {
        self.header("Connection").map(|v| !v.to_lowercase().contains("close")).unwrap_or_else(|| {
            self.version == HttpVersion::Http11
                || self.version == HttpVersion::Http2
                || self.version == HttpVersion::Http3
        })
    }

    pub fn connection_type(&self) -> String {
        self.header("Connection").cloned().unwrap_or_else(|| "keep-alive".to_string())
    }

    pub fn should_close_connection(&self) -> bool {
        self.header("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false)
    }
}

pub fn select_secure_http_response_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http_response(response: &HttpResponse, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpResponseBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http_response(response);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate http-response blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http_response_blob_tag(
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
        magic = HTTP_RESPONSE_BLOB_MAGIC,
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
        SecureHttpResponseBlobMeta {
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

pub fn encode_secure_http_response_auto(response: &HttpResponse, accept_encoding: &str) -> io::Result<(SecureHttpResponseBlobMeta, Vec<u8>)> {
    let selected = select_secure_http_response_algorithm(accept_encoding);
    encode_secure_http_response(response, selected)
}

pub fn decode_secure_http_response(data: &[u8]) -> io::Result<(SecureHttpResponseBlobMeta, HttpResponse)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http_response_meta(&header, body.len())?;
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

    let expected_tag = compute_http_response_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http-response blob HMAC mismatch",
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
            "http-response blob digest mismatch",
        ));
    }

    let response = deserialize_http_response(&raw_payload)?;
    Ok((meta, response))
}

fn serialize_http_response(response: &HttpResponse) -> Vec<u8> {
    response.to_bytes()
}

fn deserialize_http_response(raw_payload: &[u8]) -> io::Result<HttpResponse> {
    HttpResponse::from_bytes(raw_payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid response payload: {}", e)))
}

fn compute_http_response_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP_RESPONSE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP_RESPONSE_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_http_response_meta(header: &str, body_len: usize) -> io::Result<SecureHttpResponseBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_RESPONSE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http-response blob magic mismatch",
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
                format!("invalid secure response header line '{}'", line),
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
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure response blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure response blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure response blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure response blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing encoded-size in secure response blob")
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
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in secure response blob")
    })?;

    Ok(SecureHttpResponseBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status_code", &self.status_code)
            .field("reason_phrase", &self.reason_phrase)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_to_from_bytes() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());

        let response = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            headers,
            b"hello".to_vec(),
        );

        let bytes = response.to_bytes();
        let decoded = HttpResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.status_code(), 200);
        assert_eq!(decoded.reason_phrase(), "OK");
        assert_eq!(decoded.body(), b"hello");
    }

    #[test]
    fn test_secure_response_blob_roundtrip_identity() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let response = HttpResponse::new(
            201,
            "Created".to_string(),
            HttpVersion::Http11,
            headers,
            br#"{"ok":true}"#.to_vec(),
        );

        let (meta, blob) = response
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_response) = HttpResponse::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_response.status_code(), 201);
        assert_eq!(decoded_response.reason_phrase(), "Created");
        assert_eq!(decoded_response.body(), br#"{"ok":true}"#);
    }

    #[test]
    fn test_secure_response_blob_tamper_detection() {
        let response = HttpResponse::new(
            204,
            "No Content".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            Vec::new(),
        );

        let (_, mut blob) = response
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = HttpResponse::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}