use super::tls::{TlsCfg, TlsStream};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::http::http2::alpn::AlpnProtocol;
use crate::net::http::http2::Http2Connection;
use crate::net::http::{HttpMethod, HttpRequest, HttpResponse, HttpVersion};
use crate::net::tcp::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const RESPONSE_TAG_CONTEXT: &str = "SINGULARITY_HTTPS_SERVER_RESPONSE_V1";
const REQUEST_TAG_CONTEXT: &str = "SINGULARITY_HTTPS_SERVER_REQUEST_V1";
const HEADER_DIGEST: &str = "Digest";
const HEADER_CONTENT_LENGTH: &str = "Content-Length";
const HEADER_CONTENT_ENCODING: &str = "Content-Encoding";
const HEADER_CONNECTION: &str = "Connection";
const HEADER_NONCE: &str = "X-Singularity-Nonce";
const HEADER_REQUEST_TAG: &str = "X-Singularity-Request-Tag";
const HEADER_RESPONSE_TAG: &str = "X-Singularity-Response-Tag";
const HEADER_CONTENT_SHA256_HEX: &str = "X-Content-Sha256";

pub type HttpsHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureBodyMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub plain_size: usize,
    pub wire_size: usize,
}

#[derive(Clone, Debug)]
pub struct HttpsServerCfg {
    pub tls_config: TlsCfg,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub max_body_size: usize,
    pub keep_alive: bool,
    pub keep_alive_timeout: Duration,
    pub compression_enabled: bool,
    pub compression_level: CompressionLevel,
    pub preferred_compression: Vec<CompressionAlgorithm>,
    pub require_request_digest: bool,
    pub require_request_tag: bool,
}

pub struct HttpsServer {
    config: HttpsServerCfg,
    handler: Option<HttpsHandler>,
    listener: Option<TcpListener>,
    running: Arc<AtomicBool>,
    address: Option<SocketAddr>,
}

impl HttpsServer {
    pub fn new(tls_config: TlsCfg) -> Self {
        let mut config = HttpsServerCfg::default();
        config.tls_config = tls_config;

        Self {
            config,
            handler: None,
            listener: None,
            running: Arc::new(AtomicBool::new(false)),
            address: None,
        }
    }

    pub fn with_config(self, config: HttpsServerCfg) -> Self {
        Self {
            config,
            handler: None,
            listener: None,
            running: Arc::new(AtomicBool::new(false)),
            address: None,
        }
    }

    pub fn set_handler<F>(&mut self, handler: F) where F: Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static {
        self.handler = Some(Arc::new(handler));
    }

    pub fn bind(&mut self, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        self.address = Some(addr);
        self.listener = Some(listener);

        Ok(())
    }

    pub fn start(&mut self) -> std::io::Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Server not bound to an address")
        })?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        let handler = self.handler.clone();
        listener.set_read_timeout(Some(config.request_timeout))?;
        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    let config = config.clone();
                    let handler = handler.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, peer_addr, config, handler) {
                            eprintln!("TLS connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn start_async(&mut self) -> std::io::Result<thread::JoinHandle<std::io::Result<()>>> {
        let listener = self.listener.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Server not bound to an address")
        })?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        let handler = self.handler.clone();
        listener.set_read_timeout(Some(config.request_timeout))?;
        Ok(thread::spawn(move || {
            loop {
                if !running.load(Ordering::SeqCst) {
                    break;
                }

                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let config = config.clone();
                        let handler = handler.clone();
                        thread::spawn(move || {
                            if let Err(e) = Self::handle_connection(stream, peer_addr, config, handler) {
                                eprintln!("TLS connection error from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(e),
                }
            }

            Ok(())
        }))
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn handle_connection(stream: TcpStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        Self::handle_connection_with_alpn(stream, peer_addr, config, handler)
    }

    fn handle_connection_with_alpn(stream: TcpStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        let tls_stream = TlsStream::new_server(stream, config.tls_config.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        tls_stream.set_read_timeout(Some(config.request_timeout))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        tls_stream.set_write_timeout(Some(config.request_timeout))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        match tls_stream.get_negotiated_protocol() {
            Some(AlpnProtocol::Http2) => {
                Self::handle_http2_connection(tls_stream, peer_addr, config, handler)
            }
            Some(AlpnProtocol::Http11) | None => {
                Self::handle_http1_connection(tls_stream, peer_addr, config, handler)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unsupported ALPN protocol",
            )),
        }
    }

    fn handle_http2_connection(tls_stream: TlsStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        let tcp_stream = tls_stream.stream_into_inner()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut http2_conn = Http2Connection::new_with_alpn(tcp_stream, Some(AlpnProtocol::Http2))
            .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create HTTP/2 connection: {}", e),
            )
        })?;

        http2_conn.handshake_with_alpn(Some(AlpnProtocol::Http2))
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP/2 handshake failed: {}", e),
                )
        })?;

        loop {
            if http2_conn.goaway_received {
                break;
            }

            match http2_conn.receive_frames() {
                Ok(_) => {
                    Self::process_http2_streams(&mut http2_conn, &handler, peer_addr, &config)?;
                }
                Err(e) => {
                    if e.to_string().to_ascii_lowercase().contains("would block") {
                        let _ = http2_conn.send_pending_data();
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }

                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("HTTP/2 receive error: {}", e),
                    ));
                }
            }
        }

        let _ = http2_conn.close();
        Ok(())
    }

    fn process_http2_streams(http2_conn: &mut Http2Connection, handler: &Option<HttpsHandler>, peer_addr: SocketAddr, config: &HttpsServerCfg) -> std::io::Result<()> {
        let stream_ids: Vec<u32> = http2_conn.streams.keys().cloned().collect();
        for stream_id in stream_ids {
            let (method, path, raw_headers) = {
                let stream = match http2_conn.get_stream(stream_id) {
                    Some(s) => s,
                    None => continue,
                };

                if !stream.headers_received {
                    continue;
                }

                let headers = stream.response_headers().to_vec();
                let method = headers.iter().find(|(k, _)| k == ":method").map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "GET".to_string());

                let path = headers.iter().find(|(k, _)| k == ":path").map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "/".to_string());

                (method, path, headers)
            };

            let wire_body = {
                let stream = match http2_conn.get_stream(stream_id) {
                    Some(s) => s,
                    None => continue,
                };

                stream.data().to_vec()
            };

            let http_method = match HttpMethod::from_str(&method) {
                Some(m) => m,
                None => {
                    eprintln!("Invalid HTTP method from {}: {}", peer_addr, method);
                    continue;
                }
            };

            let mut header_map = HashMap::new();
            for (name, value) in &raw_headers {
                if !name.starts_with(':') {
                    header_map.insert(name.clone(), value.clone());
                }
            }

            Self::verify_request_integrity(&method, &path, &header_map, &wire_body, config)?;
            let decoded_body = Self::decode_body_from_headers(&header_map, &wire_body)?;
            let mut request = HttpRequest::new(http_method, &path).version(HttpVersion::Http2);
            for (name, value) in &header_map {
                request.set_header(name.clone(), value.clone());
            }

            if !decoded_body.is_empty() {
                request = request.set_body(decoded_body);
            }

            let response = if let Some(h) = handler {
                h(&request)
            } else {
                Self::default_h2_handler(&request)
            };

            let accept_encoding = Self::get_header_ci(&header_map, "accept-encoding");
            Self::send_http2_response(http2_conn, stream_id, &response, accept_encoding, config)?;

            let _ = http2_conn.close_stream(stream_id);
        }

        Ok(())
    }

    fn send_http2_response(http2_conn: &mut Http2Connection, stream_id: u32, response: &HttpResponse, accept_encoding: Option<&str>, config: &HttpsServerCfg) -> std::io::Result<()> {
        let (meta, wire_body) = Self::prepare_secure_response_body(
            response.status_code(),
            response.reason_phrase(),
            response.body(),
            accept_encoding,
            config,
        )?;

        let mut headers = vec![(":status".to_string(), response.status_code().to_string())];
        for (name, value) in response.headers() {
            if !Self::is_controlled_response_header(name) {
                headers.push((name.clone(), value.clone()));
            }
        }

        if !wire_body.is_empty() {
            headers.push((HEADER_CONTENT_LENGTH.to_string(), wire_body.len().to_string()));
        }

        if meta.algorithm != CompressionAlgorithm::Identity {
            headers.push((
                HEADER_CONTENT_ENCODING.to_string(),
                meta.algorithm.content_encoding().to_string(),
            ));
        }

        headers.push((HEADER_DIGEST.to_string(), format!("SHA-256={}", meta.digest_b64)));
        headers.push((HEADER_CONTENT_SHA256_HEX.to_string(), Self::to_hex(&sha256(&wire_body))));
        headers.push((HEADER_NONCE.to_string(), meta.nonce_b64));
        headers.push((HEADER_RESPONSE_TAG.to_string(), meta.tag_b64));
        http2_conn.send_request(stream_id, headers, Some(wire_body)).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP/2 send failed: {}", e),
                )
            })
    }

    fn handle_http1_connection(mut tls_stream: TlsStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        let cloned_stream = tls_stream.try_clone()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut reader = BufReader::new(cloned_stream);
        loop {
            match Self::parse_request(&mut reader, &config) {
                Ok(request) => {
                    let response = if let Some(ref h) = handler {
                        h(&request)
                    } else {
                        Self::default_handler(&request)
                    };

                    let accept_encoding = request.headers().get("accept-encoding");
                    let keep_alive = config.keep_alive && request.wants_keep_alive();
                    let response_bytes = Self::serialize_response(&response, accept_encoding, keep_alive, &config)?;
                    tls_stream.write_all(&response_bytes)?;
                    tls_stream.flush()?;
                    if !keep_alive {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error parsing HTTPS request from {}: {}", peer_addr, e);
                    let err_response = Self::error_response(400, "Bad Request");
                    let response_bytes = Self::serialize_response(&err_response, None, false, &config)
                        .unwrap_or_else(|_| err_response.to_bytes());

                    let _ = tls_stream.write_all(&response_bytes);
                    let _ = tls_stream.flush();
                    break;
                }
            }
        }

        Ok(())
    }

    fn parse_request(reader: &mut BufReader<TlsStream>, config: &HttpsServerCfg) -> std::io::Result<HttpRequest> {
        let mut request_line = String::new();
        loop {
            request_line.clear();
            let n = reader.read_line(&mut request_line)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }

            if !request_line.trim().is_empty() {
                break;
            }
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid request line",
            ));
        }

        let method = HttpMethod::from_str(parts[0]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown HTTP method")
        })?;

        let path = parts[1].to_string();
        let version = HttpVersion::from_str(parts[2]).unwrap_or(HttpVersion::Http11);
        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        loop {
            let mut header_line = String::new();
            let n = reader.read_line(&mut header_line)?;
            if n == 0 || header_line.trim().is_empty() {
                break;
            }

            if let Some(colon_pos) = header_line.find(':') {
                let key = header_line[..colon_pos].trim().to_string();
                let value = header_line[colon_pos + 1..].trim().to_string();
                if key.eq_ignore_ascii_case(HEADER_CONTENT_LENGTH) {
                    content_length = value.parse::<usize>().unwrap_or(0);
                }

                headers.insert(key, value);
            }
        }

        if content_length > config.max_body_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }

        let mut wire_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut wire_body)?;
        }

        Self::verify_request_integrity(parts[0], &path, &headers, &wire_body, config)?;
        let decoded_body = Self::decode_body_from_headers(&headers, &wire_body)?;
        let mut request = HttpRequest::new(method, &path).version(version);
        for (key, value) in &headers {
            request.set_header(key.clone(), value.clone());
        }

        request = request.set_body(decoded_body);
        Ok(request)
    }

    fn serialize_response(response: &HttpResponse, accept_encoding: Option<&str>, keep_alive: bool, config: &HttpsServerCfg) -> std::io::Result<Vec<u8>> {
        let (meta, wire_body) = Self::prepare_secure_response_body(
            response.status_code(),
            response.reason_phrase(),
            response.body(),
            accept_encoding,
            config,
        )?;

        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if !Self::is_controlled_response_header(name) {
                headers.insert(name.clone(), value.clone());
            }
        }

        if !wire_body.is_empty() {
            headers.insert(HEADER_CONTENT_LENGTH.to_string(), wire_body.len().to_string());
        }

        if meta.algorithm != CompressionAlgorithm::Identity {
            headers.insert(
                HEADER_CONTENT_ENCODING.to_string(),
                meta.algorithm.content_encoding().to_string(),
            );
        }

        headers.insert(HEADER_DIGEST.to_string(), format!("SHA-256={}", meta.digest_b64));
        headers.insert(HEADER_CONTENT_SHA256_HEX.to_string(), Self::to_hex(&sha256(&wire_body)));
        headers.insert(HEADER_NONCE.to_string(), meta.nonce_b64);
        headers.insert(HEADER_RESPONSE_TAG.to_string(), meta.tag_b64);
        if !headers.keys().any(|k| k.eq_ignore_ascii_case(HEADER_CONNECTION)) {
            headers.insert(
                HEADER_CONNECTION.to_string(),
                if keep_alive {
                    "keep-alive".to_string()
                } else {
                    "close".to_string()
                },
            );
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            format!(
                "{} {} {}\r\n",
                response.version().as_str(),
                response.status_code(),
                response.reason_phrase()
            )
            .as_bytes(),
        );

        for (key, value) in &headers {
            bytes.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&wire_body);

        Ok(bytes)
    }

    fn prepare_secure_response_body(status_code: u16, reason_phrase: &str, body: &[u8], accept_encoding: Option<&str>, config: &HttpsServerCfg) -> std::io::Result<(SecureBodyMeta, Vec<u8>)> {
        let algorithm = if config.compression_enabled && !body.is_empty() {
            Self::select_algorithm_from_accept_encoding(
                accept_encoding.unwrap_or(""),
                &config.preferred_compression,
            )
        } else {
            CompressionAlgorithm::Identity
        };

        let wire_body = if algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::compress(algorithm, body, config.compression_level)?
        };

        let mut nonce = [0u8; 16];
        random::fill_random(&mut nonce).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to generate response nonce: {}", e),
            )
        })?;

        let digest = sha256(&wire_body);
        let tag = Self::compute_response_tag(status_code, reason_phrase, &nonce, &wire_body);
        let meta = SecureBodyMeta {
            algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            plain_size: body.len(),
            wire_size: wire_body.len(),
        };

        Ok((meta, wire_body))
    }

    fn verify_request_integrity(method: &str, path: &str, headers: &HashMap<String, String>, wire_body: &[u8], config: &HttpsServerCfg) -> std::io::Result<()> {
        let digest_verified = Self::verify_request_digest(headers, wire_body)?;
        if config.require_request_digest && !wire_body.is_empty() && !digest_verified {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request digest required but missing",
            ));
        }

        let tag_verified = Self::verify_request_tag(method, path, headers, wire_body)?;
        if config.require_request_tag && !wire_body.is_empty() && !tag_verified {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request security tag required but missing",
            ));
        }

        Ok(())
    }

    fn verify_request_digest(headers: &HashMap<String, String>, wire_body: &[u8]) -> std::io::Result<bool> {
        let Some(digest_header) = Self::get_header_ci(headers, "digest") else {
            return Ok(false);
        };

        let mut saw_sha256 = false;
        let mut matched = false;
        for part in digest_header.split(',') {
            let p = part.trim();
            let mut kv = p.splitn(2, '=');
            let algo = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = kv.next().unwrap_or("").trim();
            if algo != "sha-256" {
                continue;
            }

            saw_sha256 = true;
            let expected = pem::decode(value).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request digest")
            })?;

            let actual = sha256(wire_body);
            if constant_time_eq(&expected, &actual) {
                matched = true;
                break;
            }
        }

        if saw_sha256 && !matched {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request digest verification failed",
            ));
        }

        Ok(saw_sha256 && matched)
    }

    fn verify_request_tag(method: &str, path: &str, headers: &HashMap<String, String>, wire_body: &[u8]) -> std::io::Result<bool> {
        let Some(nonce_b64) = Self::get_header_ci(headers, HEADER_NONCE) else {
            return Ok(false);
        };

        let Some(tag_b64) = Self::get_header_ci(headers, HEADER_REQUEST_TAG) else {
            return Ok(false);
        };

        let nonce = pem::decode(nonce_b64).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request nonce")
        })?;

        let expected = pem::decode(tag_b64).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request tag")
        })?;

        let actual = Self::compute_request_tag(method, path, &nonce, wire_body);
        if !constant_time_eq(&expected, &actual) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request security tag verification failed",
            ));
        }

        Ok(true)
    }

    fn decode_body_from_headers(headers: &HashMap<String, String>, wire_body: &[u8]) -> std::io::Result<Vec<u8>> {
        let Some(content_encoding) = Self::get_header_ci(headers, "content-encoding") else {
            return Ok(wire_body.to_vec());
        };

        let encoding = content_encoding.split(',').next().unwrap_or(content_encoding).trim().to_ascii_lowercase();
        if encoding.is_empty() || encoding == "identity" {
            return Ok(wire_body.to_vec());
        }

        let algo = CompressionAlgorithm::from_content_encoding(&encoding).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported content-encoding: {}", encoding),
            )
        })?;

        compression::decompress(algo, wire_body)
    }

    fn select_algorithm_from_accept_encoding(accept_encoding: &str, preferred: &[CompressionAlgorithm]) -> CompressionAlgorithm {
        let accepted = compression::parse_accept_encoding(accept_encoding);
        if accepted.is_empty() {
            return CompressionAlgorithm::Identity;
        }

        if !preferred.is_empty() {
            for pref in preferred {
                if accepted
                    .iter()
                    .any(|(alg, q)| alg == pref && *q > 0.0 && alg.is_implemented())
                {
                    return *pref;
                }
            }
        }

        for (alg, q) in accepted {
            if q > 0.0 && alg != CompressionAlgorithm::Identity && alg.is_implemented() {
                return alg;
            }
        }

        CompressionAlgorithm::Identity
    }

    fn compute_request_tag(method: &str, path: &str, nonce: &[u8], wire_body: &[u8]) -> [u8; 32] {
        let mut material = Vec::with_capacity(
            REQUEST_TAG_CONTEXT.len() + method.len() + path.len() + nonce.len() + wire_body.len() + 16,
        );

        material.extend_from_slice(REQUEST_TAG_CONTEXT.as_bytes());
        material.extend_from_slice(method.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(path.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(nonce);
        material.extend_from_slice(&(wire_body.len() as u64).to_be_bytes());
        material.extend_from_slice(wire_body);

        sha256(&material)
    }

    fn compute_response_tag(status_code: u16, reason_phrase: &str, nonce: &[u8], wire_body: &[u8]) -> [u8; 32] {
        let mut material = Vec::with_capacity(
            RESPONSE_TAG_CONTEXT.len() + reason_phrase.len() + nonce.len() + wire_body.len() + 16,
        );

        material.extend_from_slice(RESPONSE_TAG_CONTEXT.as_bytes());
        material.extend_from_slice(&status_code.to_be_bytes());
        material.extend_from_slice(reason_phrase.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(nonce);
        material.extend_from_slice(&(wire_body.len() as u64).to_be_bytes());
        material.extend_from_slice(wire_body);

        sha256(&material)
    }

    fn get_header_ci<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }

    fn is_controlled_response_header(name: &str) -> bool {
        name.eq_ignore_ascii_case(HEADER_CONTENT_LENGTH)
            || name.eq_ignore_ascii_case(HEADER_CONTENT_ENCODING)
            || name.eq_ignore_ascii_case(HEADER_DIGEST)
            || name.eq_ignore_ascii_case(HEADER_CONTENT_SHA256_HEX)
            || name.eq_ignore_ascii_case(HEADER_NONCE)
            || name.eq_ignore_ascii_case(HEADER_RESPONSE_TAG)
    }

    fn default_h2_handler(request: &HttpRequest) -> HttpResponse {
        let body = format!(
            "{{\n  \"status\": \"404\",\n  \"message\": \"Not Found\",\n  \"path\": \"{}\",\n  \"method\": \"{}\"\n}}",
            request.path(),
            request.method().as_str()
        );

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        headers.insert("x-xss-protection".to_string(), "1; mode=block".to_string());

        HttpResponse::new(
            404,
            "Not Found".to_string(),
            HttpVersion::Http2,
            headers,
            body.into_bytes(),
        )
    }

    fn default_handler(request: &HttpRequest) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>Path: {}</p></body></html>",
            request.path()
        );

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

        HttpResponse::new(
            404,
            "Not Found".to_string(),
            HttpVersion::Http11,
            headers,
            body.into_bytes(),
        )
    }

    fn error_response(status_code: u16, reason_phrase: &str) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>{} {}</h1></body></html>",
            status_code, reason_phrase
        );

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        HttpResponse::new(
            status_code,
            reason_phrase.to_string(),
            HttpVersion::Http11,
            headers,
            body.into_bytes(),
        )
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

impl Default for HttpsServerCfg {
    fn default() -> Self {
        Self {
            tls_config: TlsCfg::default(),
            max_connections: 100,
            request_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024,
            keep_alive: true,
            keep_alive_timeout: Duration::from_secs(60),
            compression_enabled: true,
            compression_level: CompressionLevel::Default,
            preferred_compression: vec![
                CompressionAlgorithm::Zstd,
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Deflate,
            ],
            require_request_digest: false,
            require_request_tag: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_server_creation() {
        let server = HttpsServer::new(TlsCfg::default());
        assert!(!server.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_select_algorithm_from_accept_encoding() {
        let preferred = vec![
            CompressionAlgorithm::Brotli,
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Gzip,
        ];

        let selected =
            HttpsServer::select_algorithm_from_accept_encoding("gzip, br;q=0.9, identity;q=0.1", &preferred);

        assert_eq!(selected, CompressionAlgorithm::Brotli);
    }

    #[test]
    fn test_verify_request_digest_ok() {
        let body = b"hello secure world".to_vec();
        let mut headers = HashMap::new();
        headers.insert(
            "Digest".to_string(),
            format!("SHA-256={}", pem::encode(&sha256(&body))),
        );

        let ok = HttpsServer::verify_request_digest(&headers, &body).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_request_digest_tampered() {
        let body = b"hello secure world".to_vec();
        let mut headers = HashMap::new();
        headers.insert(
            "Digest".to_string(),
            format!("SHA-256={}", pem::encode(&sha256(b"other body"))),
        );

        let err = HttpsServer::verify_request_digest(&headers, &body).unwrap_err();
        assert!(
            err.to_string()
                .to_ascii_lowercase()
                .contains("digest verification failed")
        );
    }

    #[test]
    fn test_verify_request_tag_ok() {
        let method = "POST";
        let path = "/api/v1/data";
        let wire_body = b"{\"ok\":true}".to_vec();
        let nonce = b"0123456789abcdef".to_vec();

        let tag = HttpsServer::compute_request_tag(method, path, &nonce, &wire_body);
        let mut headers = HashMap::new();
        headers.insert(HEADER_NONCE.to_string(), pem::encode(&nonce));
        headers.insert(HEADER_REQUEST_TAG.to_string(), pem::encode(&tag));

        let ok = HttpsServer::verify_request_tag(method, path, &headers, &wire_body).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_prepare_secure_response_body_identity() {
        let cfg = HttpsServerCfg::default();
        let (meta, wire) = HttpsServer::prepare_secure_response_body(
            200,
            "OK",
            b"small body",
            Some("identity"),
            &cfg,
        )
        .unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(wire, b"small body");
        assert!(!meta.digest_b64.is_empty());
        assert!(!meta.tag_b64.is_empty());
    }
}