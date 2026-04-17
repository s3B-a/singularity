use super::compression::{self, CompressionAlgorithm, CompressionConfig, CompressionLevel};
use super::negotiation::ContentNegotiator;
use super::{HttpMethod, HttpRequest, HttpResponse, HttpVersion};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::tcp::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HTTP_SERVER_PROFILE_BLOB_MAGIC: &str = "SINGULARITY_HTTP_SERVER_PROFILE_BLOB_V1";
const HTTP_SERVER_PROFILE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_SERVER_PROFILE_BLOB_BINDING_V1";

pub type HttpHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpServerProfileMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Clone, Debug)]
pub struct HttpServerCfg {
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub max_body_size: usize,
    pub keep_alive_timeout: Duration,
    pub keep_alive: bool,
    pub default_version: HttpVersion,
}

pub struct HttpServer {
    cfg: HttpServerCfg,
    handler: Option<HttpHandler>,
    listener: Option<TcpListener>,
    running: Arc<AtomicBool>,
    address: Option<SocketAddr>,
}

impl HttpServer {
    pub fn new() -> Self {
        Self {
            cfg: HttpServerCfg::default(),
            handler: None,
            listener: None,
            running: Arc::new(AtomicBool::new(false)),
            address: None,
        }
    }

    pub fn with_cfg(config: HttpServerCfg) -> Self {
        Self {
            cfg: config,
            handler: None,
            listener: None,
            running: Arc::new(AtomicBool::new(false)),
            address: None,
        }
    }

    pub fn set_handler<F>(&mut self, handler: F) where F: Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static {
        self.handler = Some(Arc::new(handler));
    }

    pub fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        self.address = Some(addr);
        self.listener = Some(listener);

        Ok(())
    }

    pub fn start(&mut self) -> io::Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Server not bound to an address")
        })?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let config = self.cfg.clone();
        let handler = self.handler.take();
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
                            eprintln!("Connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn start_async(&mut self) -> io::Result<thread::JoinHandle<io::Result<()>>> {
        let listener = self.listener.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Server not bound to an address")
        })?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let config = self.cfg.clone();
        let handler = self.handler.take();
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
                                eprintln!("Connection error from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            Ok(())
        }))
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn to_secure_profile_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpServerProfileMeta, Vec<u8>)> {
        encode_secure_http_server_profile(self, algorithm)
    }

    pub fn to_secure_profile_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpServerProfileMeta, Vec<u8>)> {
        encode_secure_http_server_profile_auto(self, accept_encoding)
    }

    pub fn from_secure_profile_blob(data: &[u8]) -> io::Result<(SecureHttpServerProfileMeta, HttpServer)> {
        decode_secure_http_server_profile(data)
    }

    fn handle_connection(mut stream: TcpStream, _peer_addr: SocketAddr, config: HttpServerCfg, handler: Option<HttpHandler>) -> io::Result<()> {
        stream.set_read_timeout(Some(config.request_timeout))?;
        stream.set_write_timeout(Some(config.request_timeout))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        loop {
            match Self::parse_request(&mut reader, &config) {
                Ok(request) => {
                    let base_response = if let Some(ref h) = handler {
                        h(&request)
                    } else {
                        Self::default_handler(&request)
                    };

                    let finalized = Self::finalize_response_for_request(&request, base_response)?;
                    let response_bytes = Self::serialize_response(&finalized);
                    stream.write_all(&response_bytes)?;
                    stream.flush()?;
                    if !config.keep_alive || request.headers().get("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false) || finalized.headers().get("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false) {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Request parse error: {}", e);
                    let err_response = Self::error_response(400, "Bad Request");
                    let response_bytes = Self::serialize_response(&err_response);
                    let _ = stream.write_all(&response_bytes);
                    break;
                }
            }
        }

        Ok(())
    }

    fn parse_request(reader: &mut BufReader<TcpStream>, config: &HttpServerCfg) -> io::Result<HttpRequest> {
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid request line",
            ));
        }

        let method = match parts[0] {
            "GET" => HttpMethod::GET,
            "POST" => HttpMethod::POST,
            "PUT" => HttpMethod::PUT,
            "DELETE" => HttpMethod::DELETE,
            "HEAD" => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "PATCH" => HttpMethod::PATCH,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported HTTP method",
                ));
            }
        };

        let path = parts[1].to_string();
        let _version = match parts[2] {
            "HTTP/1.0" => HttpVersion::Http10,
            "HTTP/1.1" => HttpVersion::Http11,
            "HTTP/2.0" => HttpVersion::Http2,
            _ => HttpVersion::Http11,
        };

        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line)?;
            if header_line.trim().is_empty() {
                break;
            }

            if let Some(colon_pos) = header_line.find(':') {
                let key = header_line[..colon_pos].trim().to_string();
                let value = header_line[colon_pos + 1..].trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }

                headers.insert(key, value);
            }
        }

        let mut body = Vec::new();
        if content_length > 0 {
            if content_length > config.max_body_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Request body too large",
                ));
            }

            body.resize(content_length, 0);
            reader.read_exact(&mut body)?;
        }

        if let Some(enc) = Self::get_header_case_insensitive(&headers, "content-encoding") {
            if !enc.eq_ignore_ascii_case("identity") && !body.is_empty() {
                let algo = CompressionAlgorithm::from_content_encoding(&enc.to_ascii_lowercase()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unsupported content-encoding: {}", enc),
                    )
                })?;

                body = compression::decompress(algo, &body)?;
            }
        }

        if let Some(digest_header) = Self::get_header_case_insensitive(&headers, "digest") {
            Self::verify_digest_header(&body, &digest_header)?;
        }

        let mut request = HttpRequest::new(method, path);
        for (key, value) in headers {
            request.headers_mut().insert(key, value);
        }

        request = request.set_body(body);

        Ok(request)
    }

    fn finalize_response_for_request(request: &HttpRequest, response: HttpResponse) -> io::Result<HttpResponse> {
        let mut headers = response.headers().clone();
        let mut body = response.body().to_vec();
        if !headers.contains_key("Content-Type") {
            headers.insert(
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            );
        }

        if !body.is_empty() && !headers.contains_key("Content-Encoding") {
            let cfg = CompressionConfig::default();
            let content_type = headers.get("Content-Type").cloned().unwrap_or_else(|| "application/octet-stream".to_string());
            if cfg.enabled && cfg.should_compress_size(body.len()) && cfg.should_compress_content_type(&content_type) {
                let chosen = if let Some(accept_encoding) = request.accept_encoding() {
                    cfg.negotiate_algorithm(accept_encoding)
                } else {
                    Some(CompressionAlgorithm::Identity)
                };

                if let Some(algo) = chosen {
                    if algo != CompressionAlgorithm::Identity {
                        body = compression::compress(algo, &body, cfg.level)?;
                        headers.insert(
                            "Content-Encoding".to_string(),
                            algo.content_encoding().to_string(),
                        );
                    }
                }
            }
        }

        headers.insert("Content-Length".to_string(), body.len().to_string());
        let digest_b64 = pem::encode(&sha256(&body));
        headers.insert("Digest".to_string(), format!("SHA-256={}", digest_b64));
        headers.insert("X-Content-SHA256".to_string(), Self::to_hex(&sha256(&body)));

        Ok(HttpResponse::new(
            response.status_code(),
            response.reason_phrase().to_string(),
            response.version(),
            headers,
            body,
        ))
    }

    fn serialize_response(response: &HttpResponse) -> Vec<u8> {
        let mut result = Vec::new();
        let status_line = format!(
            "{} {} {}\r\n",
            response.version().as_str(),
            response.status_code(),
            response.reason_phrase()
        );

        result.extend_from_slice(status_line.as_bytes());
        for (key, value) in response.headers() {
            result.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        if response.headers().get("Content-Length").is_none() && !response.body().is_empty() {
            result.extend_from_slice(
                format!("Content-Length: {}\r\n", response.body().len()).as_bytes(),
            );
        }

        result.extend_from_slice(b"\r\n");
        result.extend_from_slice(response.body());
        result
    }

    fn default_handler(request: &HttpRequest) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>The requested URL was not found on this path: {}</p></body></html>",
            request.path()
        );

        HttpResponse::new(
            404,
            "Not Found".to_string(),
            HttpVersion::Http11,
            {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "text/html".to_string());
                headers
            },
            body.into_bytes(),
        )
    }

    fn error_response(status_code: u16, reason: &str) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>{} {}</h1></body></html>",
            status_code, reason
        );

        HttpResponse::new(
            status_code,
            reason.to_string(),
            HttpVersion::Http11,
            {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "text/html".to_string());
                headers
            },
            body.into_bytes(),
        )
    }

    pub fn negotiate_content_type(request: &HttpRequest, available: &[&str]) -> Option<String> {
        if let Some(accept) = request.accept() {
            ContentNegotiator::negotiate_media_type(accept, available)
        } else {
            available.first().map(|s| s.to_string())
        }
    }

    pub fn negotiate_language(request: &HttpRequest, available: &[&str]) -> Option<String> {
        if let Some(accept_lang) = request.accept_language() {
            ContentNegotiator::negotiate_language(accept_lang, available)
        } else {
            available.first().map(|s| s.to_string())
        }
    }

    pub fn negotiate_encoding(request: &HttpRequest, available: &[&str]) -> Option<String> {
        if let Some(accept_enc) = request.accept_encoding() {
            ContentNegotiator::negotiate_encoding(accept_enc, available)
        } else {
            Some("identity".to_string())
        }
    }

    fn get_header_case_insensitive(headers: &HashMap<String, String>, key: &str) -> Option<String> {
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.clone())
    }

    fn verify_digest_header(body: &[u8], digest_header: &str) -> io::Result<()> {
        let mut has_sha256 = false;
        let mut matched = false;
        for part in digest_header.split(',') {
            let p = part.trim();
            let mut kv = p.splitn(2, '=');
            let algo = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = kv.next().unwrap_or("").trim();
            if algo == "sha-256" {
                has_sha256 = true;
                let expected = pem::decode(value).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid digest encoding: {}", e),
                    )
                })?;

                let actual = sha256(body);
                if constant_time_eq(&expected, &actual) {
                    matched = true;
                }
            }
        }

        if has_sha256 && matched {
            Ok(())
        } else if has_sha256 {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Digest verification failed",
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing SHA-256 digest entry",
            ))
        }
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

pub fn select_secure_http_server_profile_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http_server_profile(server: &HttpServer, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpServerProfileMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http_server_profile(server);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate server profile nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http_server_profile_blob_tag(
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
        magic = HTTP_SERVER_PROFILE_BLOB_MAGIC,
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
        SecureHttpServerProfileMeta {
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

pub fn encode_secure_http_server_profile_auto(server: &HttpServer, accept_encoding: &str) -> io::Result<(SecureHttpServerProfileMeta, Vec<u8>)> {
    let selected = select_secure_http_server_profile_algorithm(accept_encoding);
    encode_secure_http_server_profile(server, selected)
}

pub fn decode_secure_http_server_profile(data: &[u8]) -> io::Result<(SecureHttpServerProfileMeta, HttpServer)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http_server_profile_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid profile nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid profile digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid profile tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "profile digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_http_server_profile_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http-server profile HMAC mismatch",
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
                "profile raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http-server profile digest mismatch",
        ));
    }

    let server = deserialize_http_server_profile(&raw_payload)?;
    Ok((meta, server))
}

fn serialize_http_server_profile(server: &HttpServer) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!("max-connections={}", server.cfg.max_connections));
    lines.push(format!(
        "request-timeout-ms={}",
        server.cfg.request_timeout.as_millis()
    ));

    lines.push(format!("max-body-size={}", server.cfg.max_body_size));
    lines.push(format!(
        "keep-alive-timeout-ms={}",
        server.cfg.keep_alive_timeout.as_millis()
    ));
    
    lines.push(format!("keep-alive={}", server.cfg.keep_alive));
    lines.push(format!(
        "default-version={}",
        server.cfg.default_version.as_str()
    ));

    lines.push(format!("handler-installed={}", server.handler.is_some()));
    lines.push(format!(
        "running={}",
        server.running.load(Ordering::SeqCst)
    ));

    if let Some(addr) = server.address {
        lines.push(format!("address={}", pem::encode(addr.to_string().as_bytes())));
    } else {
        lines.push("address=".to_string());
    }

    lines.join("\n").into_bytes()
}

fn deserialize_http_server_profile(raw_payload: &[u8]) -> io::Result<HttpServer> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "http-server profile payload is not valid UTF-8",
        )
    })?;

    let mut cfg = HttpServerCfg::default();
    let mut address: Option<SocketAddr> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid server profile line '{}'", trimmed),
            )
        })?;

        match key {
            "max-connections" => {
                cfg.max_connections = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid max-connections")
                })?;
            }
            "request-timeout-ms" => {
                cfg.request_timeout = Duration::from_millis(value.trim().parse::<u64>().map_err(
                    |_| io::Error::new(io::ErrorKind::InvalidData, "invalid request-timeout-ms"),
                )?);
            }
            "max-body-size" => {
                cfg.max_body_size = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid max-body-size")
                })?;
            }
            "keep-alive-timeout-ms" => {
                cfg.keep_alive_timeout =
                    Duration::from_millis(value.trim().parse::<u64>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid keep-alive-timeout-ms")
                    })?);
            }
            "keep-alive" => {
                cfg.keep_alive = parse_bool(value.trim())?;
            }
            "default-version" => {
                cfg.default_version = HttpVersion::from_str(value.trim()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid default-version")
                })?;
            }
            "address" => {
                if !value.trim().is_empty() {
                    let decoded = pem::decode(value.trim()).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid address encoding: {}", e),
                        )
                    })?;

                    let addr_str = String::from_utf8(decoded).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "decoded address is not valid UTF-8",
                        )
                    })?;

                    address = Some(addr_str.parse::<SocketAddr>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid socket address")
                    })?);
                }
            }
            "handler-installed" => {
                let _ = parse_bool(value.trim())?;
            }
            "running" => {
                let _ = parse_bool(value.trim())?;
            }
            _ => {}
        }
    }

    let mut server = HttpServer::with_cfg(cfg);
    server.address = address;
    server.listener = None;
    server.handler = None;
    server.running.store(false, Ordering::SeqCst);

    Ok(server)
}

fn compute_http_server_profile_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP_SERVER_PROFILE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP_SERVER_PROFILE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "server profile header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "server profile header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "server profile blob missing header/body separator",
    ))
}

fn parse_secure_http_server_profile_meta(header: &str, body_len: usize) -> io::Result<SecureHttpServerProfileMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_SERVER_PROFILE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid http-server profile blob magic",
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

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid server profile header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", v.trim()),
                        )
                    },
                )?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid digest header"))?.to_string();
                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid tag header"))?.to_string();
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in server profile blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in server profile blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in server profile blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in server profile blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in server profile blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in server profile blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "server profile encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttpServerProfileMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v.trim() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean '{}'", v),
        )),
    }
}

impl Default for HttpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HttpServerCfg {
    fn default() -> Self {
        Self {
            max_connections: 100,
            request_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024,
            keep_alive_timeout: Duration::from_secs(5),
            keep_alive: true,
            default_version: HttpVersion::Http11,
        }
    }
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("cfg", &self.cfg)
            .field("handler_installed", &self.handler.is_some())
            .field("listener_installed", &self.listener.is_some())
            .field("running", &self.running.load(Ordering::SeqCst))
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = HttpServer::new();
        assert!(!server.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_server_config() {
        let config = HttpServerCfg::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_secure_server_profile_roundtrip_identity() {
        let mut server = HttpServer::new();
        server.address = Some("127.0.0.1:8080".parse().unwrap());

        let (meta, blob) = server
            .to_secure_profile_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = HttpServer::from_secure_profile_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.cfg.max_connections, server.cfg.max_connections);
        assert_eq!(restored.cfg.max_body_size, server.cfg.max_body_size);
        assert_eq!(restored.cfg.keep_alive, server.cfg.keep_alive);
        assert_eq!(restored.cfg.default_version, server.cfg.default_version);
        assert_eq!(restored.address, server.address);
        assert!(!restored.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_secure_server_profile_tamper_detection() {
        let server = HttpServer::new();
        let (_, mut blob) = server
            .to_secure_profile_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = HttpServer::from_secure_profile_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}