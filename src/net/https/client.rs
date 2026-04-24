use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::connection_pool::ConnectionPool;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::http::http2::alpn::{AlpnNegotiator, AlpnProtocol};
use crate::net::http::http2::hpack::HpackCodec;
use crate::net::http::{headers::Headers, HttpMethod, HttpResponse, HttpVersion};
use crate::net::https::tls::{TlsCfg, TlsError, TlsStream};
use crate::net::tcp::TcpStream;
use crate::net::https::{decode_secure_https_payload, encode_secure_https_payload_auto};

const HTTPS_CLIENT_STATE_BLOB_MAGIC: &str = "SINGULARITY_HTTPS_CLIENT_STATE_BLOB_V1";
const HTTPS_CLIENT_STATE_CONTEXT: &str = "SINGULARITY_HTTPS_CLIENT_STATE_BINDING_V1";
const HTTPS_CLIENT_REQUEST_TAG_CONTEXT: &str = "SINGULARITY_HTTPS_CLIENT_REQUEST_TAG_V1";
const HTTPS_CLIENT_RESPONSE_TAG_CONTEXT: &str = "SINGULARITY_HTTPS_CLIENT_RESPONSE_TAG_V1";

#[derive(Debug)]
pub enum HttpsError {
    Tls(TlsError),
    Io(std::io::Error),
    InvalidUrl(String),
    InvalidResponse(String),
    Timeout,
    ConnectionFailed(String),
    TooManyRedirects,
    ProtocolNegotiationFailed(String),
    Http2Error(String),
}

#[derive(Debug, Clone)]
pub struct HttpsClientCfg {
    pub tls_cfg: TlsCfg,
    pub timeout: Duration,
    pub follow_redirect: bool,
    pub max_redirects: usize,
    pub user_agent: String,
    pub default_headers: Headers,
    pub enable_secure_envelopes: bool,
    pub enforce_response_integrity: bool,
    pub request_compression_min_size: usize,
    pub request_compression_level: CompressionLevel,
    pub preferred_request_compression: CompressionAlgorithm,
}

impl Default for HttpsClientCfg {
    fn default() -> Self {
        let mut default_headers = Headers::new();
        default_headers.insert("User-Agent", "singularity-https-client/0.1.0");
        default_headers.insert("Accept", "*/*");
        default_headers.insert("Accept-Encoding", "br, zstd, gzip, deflate, identity");
        default_headers.insert("Connection", "keep-alive");

        Self {
            tls_cfg: TlsCfg::default(),
            timeout: Duration::from_secs(30),
            follow_redirect: true,
            max_redirects: 10,
            user_agent: "singularity-https-client/0.1.0".to_string(),
            default_headers,
            enable_secure_envelopes: true,
            enforce_response_integrity: false,
            request_compression_min_size: 1024,
            request_compression_level: CompressionLevel::Default,
            preferred_request_compression: CompressionAlgorithm::Identity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpsClientStateMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsClientStateSnapshot {
    pub exported_at_unix: u64,
    pub secure_envelopes_enabled: bool,
    pub negotiated_protocols: HashMap<String, AlpnProtocol>,
}

#[derive(Debug, Clone)]
struct Http2ConnectionWrapper {
    next_stream_id: u32,
    initialized: bool,
}

#[derive(Debug)]
struct TlsStreamWrapper {
    stream: TlsStream,
    protocol: Option<AlpnProtocol>,
    host: String,
    port: u16,
    http2_conn: Option<Http2ConnectionWrapper>,
}

pub struct HttpsClient {
    cfg: HttpsClientCfg,
    connection_pool: ConnectionPool,
    alpn_negotiator: AlpnNegotiator,
    tls_connections: HashMap<String, TlsStreamWrapper>,
    negotiated_protocols: HashMap<String, AlpnProtocol>,
}

impl HttpsClient {
    pub fn new(cfg: HttpsClientCfg) -> Self {
        let mut alpn_negotiator = AlpnNegotiator::new();
        alpn_negotiator.set_server_preference(false);

        Self {
            cfg,
            connection_pool: ConnectionPool::with_limits(
                10,
                Duration::from_secs(90),
                Duration::from_secs(600),
                100,
            ),
            alpn_negotiator,
            tls_connections: HashMap::new(),
            negotiated_protocols: HashMap::new(),
        }
    }

    pub fn with_config(cfg: HttpsClientCfg) -> Self {
        Self::new(cfg)
    }

    pub fn set_alpn_protocols(&mut self, protocols: Vec<AlpnProtocol>) {
        self.alpn_negotiator = AlpnNegotiator::with_protocols(protocols);
        self.alpn_negotiator.set_server_preference(false);
    }

    pub fn get_negotiated_protocol(&self, host: &str, port: u16) -> Option<AlpnProtocol> {
        self.negotiated_protocols.get(&Self::connection_key(host, port)).copied()
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::GET, url, None, None, 0)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::POST, url, Some(body), None, 0)
    }

    pub fn put(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::PUT, url, Some(body), None, 0)
    }

    pub fn delete(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::DELETE, url, None, None, 0)
    }

    pub fn head(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::HEAD, url, None, None, 0)
    }

    pub fn patch(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::PATCH, url, Some(body), None, 0)
    }

    pub fn clear_connections(&mut self) {
        self.tls_connections.clear();
        self.connection_pool.clear();
        self.negotiated_protocols.clear();
    }

    pub fn get_connection_stats(&self) -> HashMap<String, Option<AlpnProtocol>> {
        self.tls_connections.iter().map(|(k, v)| (k.clone(), v.protocol)).collect()
    }

    pub fn export_secure_state(&self, algorithm: CompressionAlgorithm) -> Result<(SecureHttpsClientStateMeta, Vec<u8>), HttpsError> {
        let snapshot = HttpsClientStateSnapshot {
            exported_at_unix: now_unix(),
            secure_envelopes_enabled: self.cfg.enable_secure_envelopes,
            negotiated_protocols: self.negotiated_protocols.clone(),
        };

        let raw_payload = serialize_client_snapshot(&snapshot);
        let selected = if algorithm.is_implemented() {
            algorithm
        } else {
            CompressionAlgorithm::Identity
        };

        let encoded_payload = if selected == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected, &raw_payload, CompressionLevel::Default).map_err(HttpsError::Io)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            HttpsError::InvalidResponse(format!("state nonce generation failed: {}", e))
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_state_blob_tag(&nonce, raw_payload.len(), selected, &encoded_payload);
        let meta = SecureHttpsClientStateMeta {
            algorithm: selected,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix: now_unix(),
        };

        let header = format!(
            "{magic}\ncontent-encoding: {encoding}\nnonce: {nonce}\ndigest: {digest}\ntag: {tag}\nraw-size: {raw_size}\nencoded-size: {encoded_size}\nissued-at: {issued_at}\n\n",
            magic = HTTPS_CLIENT_STATE_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded_payload);

        Ok((meta, out))
    }

    pub fn export_secure_state_auto(&self, accept_encoding: &str) -> Result<(SecureHttpsClientStateMeta, Vec<u8>), HttpsError> {
        self.export_secure_state(select_state_algorithm(accept_encoding))
    }

    pub fn import_secure_state(blob: &[u8]) -> Result<(SecureHttpsClientStateMeta, HttpsClientStateSnapshot), HttpsError> {
        let (header, body) = split_header_body(blob).map_err(HttpsError::Io)?;
        let meta = parse_state_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            HttpsError::InvalidResponse(format!("invalid state nonce encoding: {}", e))
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
            HttpsError::InvalidResponse(format!("invalid state digest encoding: {}", e))
        })?;

        let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
            HttpsError::InvalidResponse(format!("invalid state tag encoding: {}", e))
        })?;

        if expected_digest.len() != 32 || provided_tag.len() != 32 {
            return Err(HttpsError::InvalidResponse(
                "state digest or tag has invalid length".to_string(),
            ));
        }

        let computed_tag = compute_state_blob_tag(&nonce, meta.raw_size, meta.algorithm, body);
        if !constant_time_eq(&computed_tag, &provided_tag) {
            return Err(HttpsError::InvalidResponse(
                "state tag verification failed".to_string(),
            ));
        }

        let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body).map_err(HttpsError::Io)?
        };

        if raw_payload.len() != meta.raw_size {
            return Err(HttpsError::InvalidResponse(format!(
                "state raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            )));
        }

        let actual_digest = sha256(&raw_payload);
        if !constant_time_eq(&actual_digest, &expected_digest) {
            return Err(HttpsError::InvalidResponse(
                "state digest verification failed".to_string(),
            ));
        }

        let snapshot = deserialize_client_snapshot(&raw_payload)?;
        Ok((meta, snapshot))
    }

    pub fn apply_state_snapshot(&mut self, snapshot: &HttpsClientStateSnapshot) {
        self.negotiated_protocols = snapshot.negotiated_protocols.clone();
    }

    fn request_with_redirects(&mut self, method: HttpMethod, url: &str, body: Option<Vec<u8>>, headers: Option<Headers>, redirect_count: usize) -> Result<HttpResponse, HttpsError> {
        if redirect_count > self.cfg.max_redirects {
            return Err(HttpsError::TooManyRedirects);
        }

        let (host, port, path) = self.parse_url(url)?;
        let mut request_headers = self.cfg.default_headers.clone();
        if let Some(ref custom_headers) = headers {
            for (name, values) in custom_headers.iter() {
                for value in values {
                    request_headers.append(name.clone(), value.clone());
                }
            }
        }

        if !request_headers.contains("host") {
            let host_value = if port == 443 {
                host.clone()
            } else if host.contains(':') && !host.starts_with('[') {
                format!("[{}]:{}", host, port)
            } else {
                format!("{}:{}", host, port)
            };

            request_headers.insert("Host", host_value);
        }

        if !request_headers.contains("user-agent") {
            request_headers.insert("User-Agent", self.cfg.user_agent.clone());
        }

        if !request_headers.contains("accept-encoding") {
            request_headers.insert("Accept-Encoding", "br, zstd, gzip, deflate, identity");
        }

        let connection_key = Self::connection_key(&host, port);
        self.get_or_create_tls_connection_with_alpn(&host, port)?;
        let protocol = self.tls_connections.get(&connection_key).and_then(|w| {
            w.protocol
        }).unwrap_or_else(|| {
            self.selected_protocol_with_fallback(None)
        });

        let response = match protocol {
            AlpnProtocol::Http2 => {
                self.send_http2_request(
                    &connection_key,
                    method,
                    &path,
                    request_headers,
                    body.clone(),
                )?
            }
            AlpnProtocol::Http11 | AlpnProtocol::Http10 => {
                self.send_http1_request(
                    &connection_key,
                    method,
                    &path,
                    request_headers,
                    body.clone(),
                )?
            }
            AlpnProtocol::Http3 => {
                return Err(HttpsError::ProtocolNegotiationFailed(
                    "HTTP/3 requires QUIC transport".to_string(),
                ))
            }
        };

        if self.cfg.follow_redirect && response.is_redirect() {
            if let Some(location) = response.header("location") {
                let redirect_url = if location.starts_with("http://") || location.starts_with("https://") || location.starts_with("//") {
                    self.resolve_url(url, location)
                } else {
                    let base = format!(
                        "https://{}:{}{}",
                        host,
                        port,
                        if path.is_empty() { "/" } else { &path }
                    );
                    self.resolve_url(&base, location)
                };

                let (next_method, next_body) = if response.status_code() == 303 {
                    (HttpMethod::GET, None)
                } else {
                    (method, body)
                };

                return self.request_with_redirects(
                    next_method,
                    &redirect_url,
                    next_body,
                    headers,
                    redirect_count + 1,
                );
            }
        }

        Ok(response)
    }

    fn get_or_create_tls_connection_with_alpn(&mut self, host: &str, port: u16) -> Result<(), HttpsError> {
        let key = Self::connection_key(host, port);
        if self.tls_connections.contains_key(&key) {
            return Ok(());
        }

        let socket_addr = if host.contains(':') && !host.starts_with('[') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };

        let tcp_stream = TcpStream::connect(&socket_addr).map_err(|e| {
            HttpsError::ConnectionFailed(e.to_string())
        })?;

        let mut tls_stream = TlsStream::new_client_with_sni(
            tcp_stream,
            self.cfg.tls_cfg.clone(),
            host.to_string(),
        ).map_err(HttpsError::Tls)?;

        let preferred_protocols = self.alpn_negotiator.supported_protocols_sorted();
        if !preferred_protocols.is_empty() {
            tls_stream.init_alpn_client(preferred_protocols);
        }

        tls_stream.set_read_timeout(Some(self.cfg.timeout)).map_err(HttpsError::Tls)?;
        tls_stream.set_write_timeout(Some(self.cfg.timeout)).map_err(HttpsError::Tls)?;
        let negotiated = tls_stream.get_negotiated_protocol();
        let selected = self.selected_protocol_with_fallback(negotiated);
        let _ = tls_stream.validate_negotiated_protocol(&[
            AlpnProtocol::Http2,
            AlpnProtocol::Http11,
            AlpnProtocol::Http10,
        ]);

        self.negotiated_protocols.insert(key.clone(), selected);
        let http2_conn = if selected == AlpnProtocol::Http2 {
            Some(Http2ConnectionWrapper {
                next_stream_id: 1,
                initialized: false,
            })
        } else {
            None
        };

        self.tls_connections.insert(
            key,
            TlsStreamWrapper {
                stream: tls_stream,
                protocol: Some(selected),
                host: host.to_string(),
                port,
                http2_conn,
            },
        );

        Ok(())
    }

    fn send_http1_request(&mut self, connection_key: &str, method: HttpMethod, path: &str, mut request_headers: Headers, body: Option<Vec<u8>>) -> Result<HttpResponse, HttpsError> {
        let mut body_bytes = body.unwrap_or_default();
        self.apply_outbound_security(&mut request_headers, &mut body_bytes)?;
        if !body_bytes.is_empty() && !request_headers.contains("content-length") {
            request_headers.insert("Content-Length", body_bytes.len().to_string());
        }

        let timeout = self.cfg.timeout;
        let response_bytes = {
            let wrapper = self.tls_connections.get_mut(connection_key).ok_or_else(|| {
                HttpsError::ConnectionFailed("Connection not found".to_string())
            })?;

            let mut request = Vec::new();
            request.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method.as_str(), path).as_bytes());
            request.extend_from_slice(request_headers.format().as_bytes());
            request.extend_from_slice(b"\r\n");
            request.extend_from_slice(&body_bytes);
            wrapper.stream.write_all(&request).map_err(HttpsError::Io)?;
            wrapper.stream.flush().map_err(HttpsError::Io)?;

            Self::read_http1_response_bytes(&mut wrapper.stream, timeout)?
        };

        self.parse_http1_response(&response_bytes)
    }

    fn send_http2_request(&mut self, connection_key: &str, method: HttpMethod, path: &str, mut request_headers: Headers, body: Option<Vec<u8>>) -> Result<HttpResponse, HttpsError> {
        let mut body_bytes = body.unwrap_or_default();
        self.apply_outbound_security(&mut request_headers, &mut body_bytes)?;
        let mut header_map: HashMap<String, String> = HashMap::new();
        header_map.insert(":method".to_string(), method.as_str().to_string());
        header_map.insert(":path".to_string(), path.to_string());
        header_map.insert(":scheme".to_string(), "https".to_string());

        let authority = request_headers.get("host").map(|s| s.to_string()).unwrap_or_default();
        header_map.insert(":authority".to_string(), authority);
        for (name, values) in request_headers.iter() {
            if name.starts_with(':') {
                continue;
            }

            if values.is_empty() {
                continue;
            }

            if values.len() == 1 {
                header_map.insert(name.clone(), values[0].clone());
            } else {
                header_map.insert(name.clone(), values.join(", "));
            }
        }

        if !body_bytes.is_empty() {
            header_map.insert("content-length".to_string(), body_bytes.len().to_string());
        }

        let mut encoder = HpackCodec::new(4096);
        let header_block = encoder.encode(&header_map);
        let timeout = self.cfg.timeout;
        let (response_header_block, response_body) = {
            let wrapper = self.tls_connections.get_mut(connection_key).ok_or_else(|| {
                HttpsError::ConnectionFailed("Connection not found".to_string())
            })?;

            if wrapper.protocol != Some(AlpnProtocol::Http2) {
                return Err(HttpsError::ProtocolNegotiationFailed(format!(
                    "Expected HTTP/2, got {:?}",
                    wrapper.protocol
                )));
            }

            if wrapper.http2_conn.is_none() {
                wrapper.http2_conn = Some(Http2ConnectionWrapper {
                    next_stream_id: 1,
                    initialized: false,
                });
            }

            let h2 = wrapper.http2_conn.as_mut().unwrap();
            if !h2.initialized {
                wrapper.stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").map_err(HttpsError::Io)?;
                let settings_frame = Self::build_http2_frame(0x04, 0x00, 0, &[]);
                wrapper.stream.write_all(&settings_frame).map_err(HttpsError::Io)?;
                wrapper.stream.flush().map_err(HttpsError::Io)?;

                h2.initialized = true;
            }

            let stream_id = h2.next_stream_id;
            h2.next_stream_id += 2;

            let end_stream_in_headers = body_bytes.is_empty();
            let headers_flags = if end_stream_in_headers { 0x05 } else { 0x04 };
            let headers_frame = Self::build_http2_frame(0x01, headers_flags, stream_id, &header_block);

            wrapper.stream.write_all(&headers_frame).map_err(HttpsError::Io)?;
            if !body_bytes.is_empty() {
                let data_frame = Self::build_http2_frame(0x00, 0x01, stream_id, &body_bytes);
                wrapper.stream.write_all(&data_frame).map_err(HttpsError::Io)?;
            }

            wrapper.stream.flush().map_err(HttpsError::Io)?;
            Self::read_http2_response_raw(&mut wrapper.stream, stream_id, timeout)?
        };

        self.parse_http2_response(&response_header_block, &response_body)
    }

    fn parse_http1_response(&self, bytes: &[u8]) -> Result<HttpResponse, HttpsError> {
        let response = HttpResponse::from_bytes(bytes).map_err(|e| {
            HttpsError::InvalidResponse(format!("failed to parse HTTP/1 response: {}", e))
        })?;

        self.maybe_decode_secure_response(response)
    }

    fn parse_http2_response(&self, header_block: &[u8], body: &[u8]) -> Result<HttpResponse, HttpsError> {
        let mut decoder = HpackCodec::new(4096);
        let decoded_headers = decoder.decode(header_block).map_err(|e| {
            HttpsError::Http2Error(format!("HPACK decode failed: {}", e))
        })?;

        let mut status_code = 200u16;
        let mut headers = HashMap::new();
        for (name, value) in decoded_headers {
            if name == ":status" {
                status_code = value.parse::<u16>().map_err(|_| {
                    HttpsError::InvalidResponse(format!("invalid HTTP/2 status code: {}", value))
                })?;
            } else if !name.starts_with(':') {
                headers.insert(name, value);
            }
        }

        let reason = HttpResponse::default_reason_phrase(status_code);
        let wire = build_synthetic_http1_response(status_code, &reason, &headers, body);
        let parsed = HttpResponse::from_bytes(&wire).map_err(|e| {
            HttpsError::InvalidResponse(format!("failed to parse synthesized HTTP/2 response: {}", e))
        })?;

        let response = HttpResponse::new(
            parsed.status_code(),
            parsed.reason_phrase().to_string(),
            HttpVersion::Http2,
            parsed.headers().clone(),
            parsed.body().to_vec(),
        );

        self.maybe_decode_secure_response(response)
    }

    fn maybe_decode_secure_response(&self, response: HttpResponse) -> Result<HttpResponse, HttpsError> {
        self.verify_optional_response_integrity(&response)?;

        let mut headers = response.headers().clone();
        let secure_marker = map_get_case_insensitive(&headers, "x-singularity-secure-envelope").unwrap_or_default();
        if !is_truthy_header(&secure_marker) {
            return Ok(response);
        }

        let (_, payload) = decode_secure_https_payload(response.body()).map_err(|e| {
            HttpsError::InvalidResponse(format!("failed to decode secure envelope: {}", e))
        })?;

        map_remove_case_insensitive(&mut headers, "x-singularity-secure-envelope");
        map_remove_case_insensitive(&mut headers, "content-encoding");
        headers.insert("content-length".to_string(), payload.len().to_string());

        Ok(HttpResponse::new(
            response.status_code(),
            response.reason_phrase().to_string(),
            response.version(),
            headers,
            payload,
        ))
    }

    fn verify_optional_response_integrity(&self, response: &HttpResponse) -> Result<(), HttpsError> {
        let headers = response.headers();
        let Some(nonce_b64) = map_get_case_insensitive(headers, "x-singularity-response-nonce") else {
            return Ok(());
        };

        let Some(tag_header) = map_get_case_insensitive(headers, "x-singularity-response-tag") else {
            return Ok(());
        };

        let nonce = pem::decode(&nonce_b64).map_err(|e| {
            HttpsError::InvalidResponse(format!("invalid response nonce encoding: {}", e))
        })?;

        let expected_tag = decode_hmac_header_value(&tag_header).map_err(|e| {
            HttpsError::InvalidResponse(e)
        })?;

        let computed_tag = compute_payload_tag(HTTPS_CLIENT_RESPONSE_TAG_CONTEXT.as_bytes(), &nonce, response.body());
        if !constant_time_eq(&computed_tag, &expected_tag) {
            if self.cfg.enforce_response_integrity {
                return Err(HttpsError::InvalidResponse(
                    "response integrity verification failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn apply_outbound_security(&self, headers: &mut Headers, body: &mut Vec<u8>) -> Result<(), HttpsError> {
        if body.is_empty() {
            return Ok(());
        }

        let digest = sha256(body);
        headers.insert("Digest", format!("SHA-256={}", pem::encode(&digest)));
        if self.cfg.enable_secure_envelopes && body.len() >= self.cfg.request_compression_min_size {
            let accept_encoding = headers.get("accept-encoding").unwrap_or("identity");
            let (_, secure_blob) = encode_secure_https_payload_auto(body, accept_encoding).map_err(|e| {
                HttpsError::InvalidResponse(format!("secure envelope encode failed: {}", e))
            })?;

            *body = secure_blob;
            headers.insert("X-Singularity-Secure-Envelope", "v1");
            headers.insert("Content-Type", "application/x-singularity-secure-envelope");
            headers.insert("Content-Encoding", "identity");
        } else if self.cfg.preferred_request_compression != CompressionAlgorithm::Identity && self.cfg.preferred_request_compression.is_implemented() && body.len() >= self.cfg.request_compression_min_size {
            let compressed = compression::compress(
                self.cfg.preferred_request_compression,
                body,
                self.cfg.request_compression_level,
            ).map_err(HttpsError::Io)?;

            if compressed.len() < body.len() {
                *body = compressed;
                headers.insert(
                    "Content-Encoding",
                    self.cfg.preferred_request_compression.content_encoding(),
                );
            }
        }

        let nonce = random::generate_random(16).map_err(|e| {
            HttpsError::InvalidResponse(format!("request nonce generation failed: {}", e))
        })?;

        let tag = compute_payload_tag(HTTPS_CLIENT_REQUEST_TAG_CONTEXT.as_bytes(), &nonce, body);

        headers.insert("X-Singularity-Request-Nonce", pem::encode(&nonce));
        headers.insert("X-Singularity-Request-Tag", format!("HMAC-SHA-256={}", pem::encode(&tag)));
        headers.insert("Content-Length", body.len().to_string());

        Ok(())
    }

    fn parse_url(&self, url: &str) -> Result<(String, u16, String), HttpsError> {
        let url = if let Some(rest) = url.strip_prefix("https://") {
            rest
        } else if url.starts_with("http://") {
            return Err(HttpsError::InvalidUrl(
                "HTTPS client requires https:// scheme".to_string(),
            ));
        } else {
            url
        };

        let (host_port, path) = match url.find('/') {
            Some(idx) => (&url[..idx], &url[idx..]),
            None => (url, "/"),
        };

        if host_port.is_empty() {
            return Err(HttpsError::InvalidUrl("missing host".to_string()));
        }

        if host_port.starts_with('[') {
            let end = host_port.find(']').ok_or_else(|| {
                HttpsError::InvalidUrl("invalid IPv6 host format".to_string())
            })?;

            let host = host_port[1..end].to_string();
            let port = if end + 1 < host_port.len() {
                let suffix = &host_port[end + 1..];
                if let Some(p) = suffix.strip_prefix(':') {
                    p.parse::<u16>().map_err(|_| {
                        HttpsError::InvalidUrl("invalid port number".to_string())
                    })?
                } else {
                    return Err(HttpsError::InvalidUrl("invalid host:port format".to_string()));
                }
            } else {
                443
            };

            return Ok((host, port, path.to_string()));
        }

        let (host, port) = if let Some(pos) = host_port.rfind(':') {
            let host_part = &host_port[..pos];
            let port_part = &host_port[pos + 1..];
            if host_part.is_empty() {
                return Err(HttpsError::InvalidUrl("missing host".to_string()));
            }

            let port = port_part.parse::<u16>().map_err(|_| {
                HttpsError::InvalidUrl("invalid port number".to_string())
            })?;

            (host_part.to_string(), port)
        } else {
            (host_port.to_string(), 443)
        };

        Ok((host, port, path.to_string()))
    }

    fn resolve_url(&self, base: &str, relative: &str) -> String {
        if relative.starts_with("https://") || relative.starts_with("http://") {
            return relative.to_string();
        }

        if relative.starts_with("//") {
            return format!("https:{}", relative);
        }

        if relative.starts_with('/') {
            if let Ok((host, port, _)) = self.parse_url(base) {
                if port == 443 {
                    return format!("https://{}{}", host, relative);
                }

                return format!("https://{}:{}{}", host, port, relative);
            }

            return relative.to_string();
        }

        let base_no_fragment = base.split('#').next().unwrap_or(base);
        let base_no_query = base_no_fragment.split('?').next().unwrap_or(base_no_fragment);
        if let Some(last_slash) = base_no_query.rfind('/') {
            format!("{}/{}", &base_no_query[..last_slash], relative)
        } else {
            format!("{}/{}", base_no_query, relative)
        }
    }

    fn selected_protocol_with_fallback(&self, negotiated: Option<AlpnProtocol>) -> AlpnProtocol {
        negotiated.unwrap_or_else(|| {
            if self.cfg.tls_cfg.max_version >= crate::net::https::tls::TlsVersion::Tls1_2 {
                AlpnProtocol::Http2
            } else {
                AlpnProtocol::Http11
            }
        })
    }

    fn connection_key(host: &str, port: u16) -> String {
        format!("{}:{}", host, port)
    }

    fn build_http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + payload.len());
        let len = payload.len() as u32;

        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);

        out
    }

    fn read_http1_response_bytes(stream: &mut TlsStream, timeout: Duration) -> Result<Vec<u8>, HttpsError> {
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        let start = Instant::now();
        let mut header_end: Option<usize> = None;
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            if start.elapsed() > timeout {
                if data.is_empty() {
                    return Err(HttpsError::Timeout);
                }

                break;
            }

            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(end) = find_http_header_end(&data) {
                            header_end = Some(end);
                            let (len, is_chunked) = parse_http1_meta(&data[..end]);
                            content_length = len;
                            chunked = is_chunked;
                        }
                    }

                    if let Some(h_end) = header_end {
                        let body = &data[h_end..];
                        if let Some(expected) = content_length {
                            if body.len() >= expected {
                                break;
                            }
                        } else if chunked && chunked_body_complete(body) {
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if !data.is_empty() {
                        break;
                    }

                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(HttpsError::Io(e)),
            }
        }

        if data.is_empty() {
            return Err(HttpsError::InvalidResponse("empty response".to_string()));
        }

        Ok(data)
    }

    fn read_http2_response_raw(stream: &mut TlsStream, target_stream_id: u32, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>), HttpsError> {
        let start = Instant::now();
        let mut recv_buf = Vec::<u8>::new();
        let mut tmp = [0u8; 16384];
        let mut header_block = Vec::new();
        let mut body = Vec::new();
        let mut end_stream = false;
        while !end_stream {
            if start.elapsed() > timeout {
                if header_block.is_empty() && body.is_empty() {
                    return Err(HttpsError::Timeout);
                }

                break;
            }

            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    recv_buf.extend_from_slice(&tmp[..n]);
                    loop {
                        if recv_buf.len() < 9 {
                            break;
                        }

                        let length = ((recv_buf[0] as usize) << 16) | ((recv_buf[1] as usize) << 8) | (recv_buf[2] as usize);
                        let frame_type = recv_buf[3];
                        let flags = recv_buf[4];
                        let stream_id = u32::from_be_bytes([
                            recv_buf[5], recv_buf[6], recv_buf[7], recv_buf[8],
                        ]) & 0x7fff_ffff;

                        if recv_buf.len() < 9 + length {
                            break;
                        }

                        let payload = recv_buf[9..9 + length].to_vec();
                        recv_buf.drain(..9 + length);
                        if frame_type == 0x04 && stream_id == 0 && (flags & 0x01) == 0 {
                            let ack = Self::build_http2_frame(0x04, 0x01, 0, &[]);
                            stream.write_all(&ack).map_err(HttpsError::Io)?;
                            stream.flush().map_err(HttpsError::Io)?;
                            continue;
                        }

                        if stream_id != target_stream_id {
                            continue;
                        }

                        match frame_type {
                            0x01 | 0x09 => {
                                header_block.extend_from_slice(&payload);
                                if (flags & 0x01) != 0 {
                                    end_stream = true;
                                }
                            }
                            0x00 => {
                                body.extend_from_slice(&payload);
                                if (flags & 0x01) != 0 {
                                    end_stream = true;
                                }
                            }
                            0x03 => {
                                return Err(HttpsError::Http2Error(
                                    "received RST_STREAM for request stream".to_string(),
                                ));
                            }
                            _ => {}
                        }

                        if end_stream {
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(HttpsError::Io(e)),
            }
        }

        if header_block.is_empty() {
            return Err(HttpsError::InvalidResponse(
                "HTTP/2 response missing headers block".to_string(),
            ));
        }

        Ok((header_block, body))
    }
}

impl Default for HttpsClient {
    fn default() -> Self {
        Self::new(HttpsClientCfg::default())
    }
}

impl From<TlsError> for HttpsError {
    fn from(err: TlsError) -> Self {
        HttpsError::Tls(err)
    }
}

impl From<std::io::Error> for HttpsError {
    fn from(err: std::io::Error) -> Self {
        HttpsError::Io(err)
    }
}

impl std::fmt::Display for HttpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpsError::Tls(e) => write!(f, "TLS error: {:?}", e),
            HttpsError::Io(e) => write!(f, "IO error: {}", e),
            HttpsError::InvalidUrl(msg) => write!(f, "invalid URL: {}", msg),
            HttpsError::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            HttpsError::Timeout => write!(f, "request timeout"),
            HttpsError::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            HttpsError::TooManyRedirects => write!(f, "too many redirects"),
            HttpsError::ProtocolNegotiationFailed(msg) => {
                write!(f, "protocol negotiation failed: {}", msg)
            }
            HttpsError::Http2Error(msg) => write!(f, "HTTP/2 error: {}", msg),
        }
    }
}

impl std::error::Error for HttpsError {}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn split_header_body(data: &[u8]) -> std::io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "header delimiter not found")
    })?;

    let header = std::str::from_utf8(&data[..split]).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "header is not valid UTF-8")
    })?.to_string();

    Ok((header, &data[split + DELIM.len()..]))
}

fn parse_state_meta(header: &str, body_len: usize) -> Result<SecureHttpsClientStateMeta, HttpsError> {
    let mut lines = header.lines();
    let magic = lines.next().ok_or_else(|| {
        HttpsError::InvalidResponse("state blob magic missing".to_string())
    })?;

    if magic != HTTPS_CLIENT_STATE_BLOB_MAGIC {
        return Err(HttpsError::InvalidResponse(
            "state blob magic mismatch".to_string(),
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = 0u64;
    for line in lines {
        let mut kv = line.splitn(2, ':');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        match key {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value).ok_or_else(|| {
                    HttpsError::InvalidResponse(format!(
                        "unsupported state content-encoding: {}",
                        value
                    ))
                })?;
            }
            "nonce" => nonce_b64 = value.to_string(),
            "digest" => digest_b64 = value.to_string(),
            "tag" => tag_b64 = value.to_string(),
            "raw-size" => {
                raw_size = Some(
                    value.parse::<usize>().map_err(|_| {
                        HttpsError::InvalidResponse("invalid raw-size".to_string())
                    })?,
                );
            }
            "encoded-size" => {
                encoded_size =
                    Some(value.parse::<usize>().map_err(|_| {
                        HttpsError::InvalidResponse("invalid encoded-size".to_string())
                    })?);
            }
            "issued-at" => {
                issued_at_unix = value.parse::<u64>().unwrap_or(0);
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(HttpsError::InvalidResponse(
            "state metadata missing nonce/digest/tag".to_string(),
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        HttpsError::InvalidResponse("state metadata missing raw-size".to_string())
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        HttpsError::InvalidResponse("state metadata missing encoded-size".to_string())
    })?;

    if encoded_size != body_len {
        return Err(HttpsError::InvalidResponse(format!(
            "state encoded-size mismatch: metadata {}, body {}",
            encoded_size, body_len
        )));
    }

    Ok(SecureHttpsClientStateMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

fn select_state_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algo, q) in accepted {
        if q > 0.0 && algo.is_implemented() && algo != CompressionAlgorithm::Identity {
            return algo;
        }
    }

    CompressionAlgorithm::Identity
}

fn compute_state_blob_tag(nonce: &[u8], raw_size: usize, algorithm: CompressionAlgorithm, encoded_payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(96 + encoded_payload.len());
    material.extend_from_slice(HTTPS_CLIENT_STATE_CONTEXT.as_bytes());
    material.extend_from_slice(nonce);
    material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    material.extend_from_slice(algorithm.content_encoding().as_bytes());
    material.push(0x0a);
    material.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    material.extend_from_slice(encoded_payload);

    hmac_sha256(HTTPS_CLIENT_STATE_CONTEXT.as_bytes(), &material)
}

fn compute_payload_tag(context_key: &[u8], nonce: &[u8], payload: &[u8]) -> [u8; 32] {
    let digest = sha256(payload);
    let mut material = Vec::with_capacity(64 + payload.len());
    material.extend_from_slice(nonce);
    material.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    material.extend_from_slice(&digest);
    material.extend_from_slice(payload);

    hmac_sha256(context_key, &material)
}

fn serialize_client_snapshot(snapshot: &HttpsClientStateSnapshot) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push("SINGULARITY_HTTPS_CLIENT_STATE_PAYLOAD_V1".to_string());
    lines.push(format!("exported-at={}", snapshot.exported_at_unix));
    lines.push(format!(
        "secure-envelopes={}",
        if snapshot.secure_envelopes_enabled { "on" } else { "off" }
    ));

    let mut entries: Vec<_> = snapshot.negotiated_protocols.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    lines.push(format!("negotiated-count={}", entries.len()));
    for (k, v) in entries {
        lines.push(format!("negotiated={}|{}", k, protocol_wire_name(*v)));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_client_snapshot(raw: &[u8]) -> Result<HttpsClientStateSnapshot, HttpsError> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        HttpsError::InvalidResponse("state payload is not valid UTF-8".to_string())
    })?;

    let mut lines = text.lines();
    let magic = lines.next().unwrap_or("");
    if magic != "SINGULARITY_HTTPS_CLIENT_STATE_PAYLOAD_V1" {
        return Err(HttpsError::InvalidResponse(
            "state payload magic mismatch".to_string(),
        ));
    }

    let mut exported_at = 0u64;
    let mut secure_envelopes_enabled = false;
    let mut negotiated = HashMap::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("exported-at=") {
            exported_at = rest.parse::<u64>().unwrap_or(0);
            continue;
        }

        if let Some(rest) = line.strip_prefix("secure-envelopes=") {
            secure_envelopes_enabled = rest.eq_ignore_ascii_case("on");
            continue;
        }

        if let Some(rest) = line.strip_prefix("negotiated=") {
            let mut parts = rest.splitn(2, '|');
            let key = parts.next().unwrap_or("").trim();
            let proto = parts.next().unwrap_or("").trim();
            if !key.is_empty() {
                if let Some(p) = protocol_from_wire_name(proto) {
                    negotiated.insert(key.to_string(), p);
                }
            }

            continue;
        }
    }

    Ok(HttpsClientStateSnapshot {
        exported_at_unix: exported_at,
        secure_envelopes_enabled,
        negotiated_protocols: negotiated,
    })
}

fn protocol_wire_name(proto: AlpnProtocol) -> &'static str {
    match proto {
        AlpnProtocol::Http2 => "h2",
        AlpnProtocol::Http11 => "http/1.1",
        AlpnProtocol::Http10 => "http/1.0",
        AlpnProtocol::Http3 => "h3",
    }
}

fn protocol_from_wire_name(name: &str) -> Option<AlpnProtocol> {
    match name {
        "h2" => Some(AlpnProtocol::Http2),
        "http/1.1" => Some(AlpnProtocol::Http11),
        "http/1.0" => Some(AlpnProtocol::Http10),
        "h3" => Some(AlpnProtocol::Http3),
        _ => None,
    }
}

fn decode_hmac_header_value(value: &str) -> Result<Vec<u8>, String> {
    let raw = if let Some((_, rhs)) = value.split_once('=') {
        rhs.trim()
    } else {
        value.trim()
    };

    pem::decode(raw).map_err(|e| format!("invalid HMAC header encoding: {}", e))
}

fn is_truthy_header(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    v == "1" || v == "true" || v == "yes" || v == "on" || v == "v1"
}

fn map_get_case_insensitive(map: &HashMap<String, String>, key: &str) -> Option<String> {
    map.iter().find(|(k, _)| {
        k.eq_ignore_ascii_case(key)
    }).map(|(_, v)| {
        v.clone()
    })
}

fn map_remove_case_insensitive(map: &mut HashMap<String, String>, key: &str) -> Option<String> {
    let existing = map.keys().find(|k| {
        k.eq_ignore_ascii_case(key)
    }).cloned()?;

    map.remove(&existing)
}

fn find_http_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| {
        w == b"\r\n\r\n"
    }).map(|idx| {
        idx + 4
    })
}

fn parse_http1_meta(header_section: &[u8]) -> (Option<usize>, bool) {
    let text = String::from_utf8_lossy(header_section);
    let mut content_length = None;
    let mut chunked = false;
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }

        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_ascii_lowercase();
            if key == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if key == "transfer-encoding" && value.contains("chunked") {
                chunked = true;
            }
        }
    }

    (content_length, chunked)
}

fn chunked_body_complete(body: &[u8]) -> bool {
    body.windows(7).any(|w| w == b"\r\n0\r\n\r\n") || body.ends_with(b"0\r\n\r\n")
}

fn build_synthetic_http1_response(status_code: u16, reason_phrase: &str, headers: &HashMap<String, String>, body: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&format!("HTTP/1.1 {} {}\r\n", status_code, reason_phrase));
    let mut has_content_length = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }

        out.push_str(&format!("{}: {}\r\n", k, v));
    }

    if !has_content_length {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_client_creation() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        assert!(client.tls_connections.is_empty());
    }

    #[test]
    fn test_parse_url_default_port() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let (host, port, path) = client.parse_url("https://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_url_custom_port() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let (host, port, path) = client.parse_url("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_resolve_relative_url() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let resolved = client.resolve_url("https://example.com/root/page", "next");

        assert_eq!(resolved, "https://example.com/root/next");
    }

    #[test]
    fn test_secure_state_roundtrip() {
        let mut client = HttpsClient::new(HttpsClientCfg::default());
        client
            .negotiated_protocols
            .insert("example.com:443".to_string(), AlpnProtocol::Http2);

        let (meta, blob) = client.export_secure_state(CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, snapshot) = HttpsClient::import_secure_state(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(
            snapshot.negotiated_protocols.get("example.com:443"),
            Some(&AlpnProtocol::Http2)
        );
    }

    #[test]
    fn test_secure_state_tamper_detection() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let (_, mut blob) = client.export_secure_state(CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let err = HttpsClient::import_secure_state(&blob).unwrap_err();
        assert!(err.to_string().contains("verification"));
    }

    #[test]
    fn test_secure_response_envelope_decode() {
        let payload = b"secure response payload".to_vec();
        let (_, blob) = crate::net::https::encode_secure_https_payload(
            &payload,
            CompressionAlgorithm::Identity,
        ).unwrap();

        let mut headers = HashMap::new();
        headers.insert("x-singularity-secure-envelope".to_string(), "v1".to_string());
        headers.insert("content-length".to_string(), blob.len().to_string());

        let response = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            headers,
            blob,
        );

        let client = HttpsClient::new(HttpsClientCfg::default());
        let decoded = client.maybe_decode_secure_response(response).unwrap();

        assert_eq!(decoded.body(), payload.as_slice());
    }

    #[test]
    fn test_apply_outbound_security_adds_headers() {
        let mut cfg = HttpsClientCfg::default();
        cfg.enable_secure_envelopes = true;
        cfg.request_compression_min_size = 1;

        let client = HttpsClient::new(cfg);
        let mut headers = Headers::new();
        headers.insert("Accept-Encoding", "gzip, identity");

        let mut body = b"hello world".to_vec();
        client.apply_outbound_security(&mut headers, &mut body).unwrap();

        assert!(headers.contains("digest"));
        assert!(headers.contains("x-singularity-request-nonce"));
        assert!(headers.contains("x-singularity-request-tag"));
        assert!(headers.contains("x-singularity-secure-envelope"));
    }

    #[test]
    fn test_response_integrity_optional_enforcement() {
        let body = b"body".to_vec();
        let nonce = random::generate_random(16).unwrap();
        let mut bad_tag = compute_payload_tag(
            HTTPS_CLIENT_RESPONSE_TAG_CONTEXT.as_bytes(),
            &nonce,
            b"tampered",
        );
        bad_tag[0] ^= 0x01;

        let mut headers = HashMap::new();
        headers.insert("x-singularity-response-nonce".to_string(), pem::encode(&nonce));
        headers.insert(
            "x-singularity-response-tag".to_string(),
            format!("HMAC-SHA-256={}", pem::encode(&bad_tag)),
        );

        let response = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            headers.clone(),
            body.clone(),
        );

        let client_non_enforcing = HttpsClient::new(HttpsClientCfg::default());
        assert!(client_non_enforcing.verify_optional_response_integrity(&response).is_ok());
        let mut strict_cfg = HttpsClientCfg::default();
        strict_cfg.enforce_response_integrity = true;
        let client_enforcing = HttpsClient::new(strict_cfg);

        let strict_resp = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            headers,
            body,
        );

        assert!(client_enforcing
            .verify_optional_response_integrity(&strict_resp)
            .is_err());
    }
}