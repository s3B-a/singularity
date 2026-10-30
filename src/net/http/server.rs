use super::chunked::{ChunkedDecoder, ChunkedLimitError, DEFAULT_MAX_CHUNK_LINE};
use super::compression::{self, CompressionAlgorithm, CompressionConfig, CompressionLevel};
use super::conditional::{evaluate_preconditions, http_date_now, if_range_matches, parse_http_date, EntityTag, PreconditionOutcome};
use super::negotiation::ContentNegotiator;
use super::range::{build_multipart_byteranges, evaluate_ranges, parse_range_header, ContentRange, RangeOutcome};
use super::{HttpMethod, HttpRequest, HttpResponse, HttpVersion};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::tcp::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
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
    pub max_request_line_size: usize,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub auto_etag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http1RequestLimits {
    pub max_request_line_size: usize,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_body_size: usize,
}

#[derive(Debug, Clone)]
pub struct Http1RawRequest {
    pub method: HttpMethod,
    pub target: String,
    pub version: HttpVersion,
    pub fields: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum Http1ReadError {
    Closed,
    Reject(u16, String),
    Io(io::Error),
}

enum Line {
    Bytes(Vec<u8>),
    Eof,
    TooLong,
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

    fn handle_connection(stream: TcpStream, _peer_addr: SocketAddr, config: HttpServerCfg, handler: Option<HttpHandler>) -> io::Result<()> {
        stream.set_read_timeout(Some(config.request_timeout))?;
        stream.set_write_timeout(Some(config.request_timeout))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        Self::serve_connection(&mut reader, &mut writer, &config, handler.as_ref())
    }

    fn serve_connection<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, config: &HttpServerCfg, handler: Option<&HttpHandler>) -> io::Result<()> {
        loop {
            let request = match Self::parse_request(reader, writer, config) {
                Ok(request) => request,
                Err(Http1ReadError::Closed) => return Ok(()),
                Err(Http1ReadError::Io(e)) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => return Ok(()),
                Err(Http1ReadError::Io(e)) => return Err(e),
                Err(Http1ReadError::Reject(status, reason)) => {
                    eprintln!("Rejecting request with {}: {}", status, reason);
                    let mut response = Self::error_response(status, &HttpResponse::default_reason_phrase(status));
                    response.set_header("Connection", "close");
                    let _ = writer.write_all(&Self::serialize_response(&response, false));
                    let _ = writer.flush();
                    return Ok(());
                }
            };

            let base_response = match handler {
                Some(h) => h(&request),
                None => Self::default_handler(&request),
            };

            let mut finalized = Self::finalize_response_for_request(&request, base_response, config)?;
            let close = !config.keep_alive || Self::wants_close(&request) || finalized.should_close_connection();
            if !finalized.has_header("Connection") {
                if close {
                    finalized.set_header("Connection", "close");
                } else if *request.version_ref() == HttpVersion::Http10 {
                    finalized.set_header("Connection", "keep-alive");
                }
            }

            writer.write_all(&Self::serialize_response(&finalized, request.method() == HttpMethod::HEAD))?;
            writer.flush()?;
            if close {
                return Ok(());
            }
        }
    }

    fn wants_close(request: &HttpRequest) -> bool {
        let connection = request.headers().get_all("connection").map(|values| values.join(",").to_ascii_lowercase()).unwrap_or_default();
        let has_option = |option: &str| connection.split(',').any(|o| o.trim() == option);
        if *request.version_ref() == HttpVersion::Http10 {
            !has_option("keep-alive")
        } else {
            has_option("close")
        }
    }

    fn parse_request<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, config: &HttpServerCfg) -> Result<HttpRequest, Http1ReadError> {
        let raw = Self::read_http1_request(reader, writer, &Http1RequestLimits::from_cfg(config))?;
        let mut body = raw.body;
        if let Some(enc) = raw.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-encoding")).map(|(_, v)| v.as_str()) {
            if !enc.eq_ignore_ascii_case("identity") && !body.is_empty() {
                let algo = CompressionAlgorithm::from_content_encoding(&enc.to_ascii_lowercase())
                    .ok_or_else(|| reject(415, format!("unsupported content-encoding {}", enc)))?;
                body = compression::decompress(algo, &body).map_err(|e| reject(400, format!("could not decode request body: {}", e)))?;
            }
        }

        if let Some(digest_header) = raw.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case("digest")).map(|(_, v)| v.as_str()) {
            Self::verify_digest_header(&body, digest_header).map_err(|e| reject(400, e.to_string()))?;
        }

        let mut request = HttpRequest::new(raw.method, raw.target).version(raw.version);
        for (name, value) in raw.fields {
            request.headers_mut().append(name, value);
        }

        Ok(request.set_body(body))
    }

    pub fn read_http1_request<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, limits: &Http1RequestLimits) -> Result<Http1RawRequest, Http1ReadError> {
        let mut request_line = None;
        for _ in 0..4 {
            match read_bounded_line(reader, limits.max_request_line_size) {
                Ok(Line::Bytes(line)) if line.is_empty() => continue,
                Ok(Line::Bytes(line)) => {
                    request_line = Some(line);
                    break;
                }
                Ok(Line::Eof) => return Err(Http1ReadError::Closed),
                Ok(Line::TooLong) => return Err(reject(414, "request line too long")),
                Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => return Err(Http1ReadError::Closed),
                Err(e) => return Err(e.into()),
            }
        }

        let request_line = request_line.ok_or_else(|| reject(400, "no request line"))?;
        let request_line = String::from_utf8(request_line).map_err(|_| reject(400, "request line is not valid UTF-8"))?;
        let parts: Vec<&str> = request_line.split(' ').collect();
        let [method, target, version] = parts.as_slice() else {
            return Err(reject(400, "malformed request line"));
        };

        if method.is_empty() || !method.bytes().all(is_tchar) {
            return Err(reject(400, "invalid method"));
        }

        let method = match *method {
            "GET" => HttpMethod::GET,
            "POST" => HttpMethod::POST,
            "PUT" => HttpMethod::PUT,
            "DELETE" => HttpMethod::DELETE,
            "HEAD" => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "PATCH" => HttpMethod::PATCH,
            _ => return Err(reject(501, format!("unsupported method {}", method))),
        };

        if target.is_empty() || !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(reject(400, "invalid request target"));
        }

        let version = match *version {
            "HTTP/1.1" => HttpVersion::Http11,
            "HTTP/1.0" => HttpVersion::Http10,
            v if v.len() == 8 && v.starts_with("HTTP/") && v.as_bytes()[5].is_ascii_digit() && v.as_bytes()[6] == b'.' && v.as_bytes()[7].is_ascii_digit() => {
                return Err(reject(505, format!("unsupported version {}", v)));
            }
            _ => return Err(reject(400, "invalid HTTP version")),
        };

        let mut fields: Vec<(String, String)> = Vec::new();
        let mut header_bytes = 0usize;
        loop {
            let remaining = limits.max_header_bytes.saturating_sub(header_bytes);
            let line = match read_bounded_line(reader, remaining)? {
                Line::Bytes(line) => line,
                Line::Eof => return Err(Http1ReadError::Closed),
                Line::TooLong => return Err(reject(431, "request header fields too large")),
            };

            if line.is_empty() {
                break;
            }

            header_bytes += line.len() + 2;
            if fields.len() >= limits.max_header_count {
                return Err(reject(431, "too many request header fields"));
            }

            if line[0] == b' ' || line[0] == b'\t' {
                return Err(reject(400, "obsolete line folding is not accepted"));
            }

            let line = String::from_utf8(line).map_err(|_| reject(400, "header field is not valid UTF-8"))?;
            let (name, value) = line.split_once(':').ok_or_else(|| reject(400, "header field without a colon"))?;
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err(reject(400, format!("invalid header field name {:?}", name)));
            }

            let value = value.trim_matches([' ', '\t']);
            if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Err(reject(400, "invalid character in header field value"));
            }

            fields.push((name.to_string(), value.to_string()));
        }

        let values = |name: &str| -> Vec<&str> {
            fields.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
        };

        let hosts = values("host");
        if hosts.len() > 1 {
            return Err(reject(400, "multiple Host header fields"));
        }

        if hosts.is_empty() && version == HttpVersion::Http11 {
            return Err(reject(400, "missing Host header field"));
        }

        if let Some(host) = hosts.first() {
            if !is_valid_host(host) {
                return Err(reject(400, format!("invalid Host header field {:?}", host)));
            }
        }

        let transfer_codings: Vec<String> = values("transfer-encoding").iter()
            .flat_map(|v| v.split(','))
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        let content_lengths: Vec<&str> = values("content-length").iter().flat_map(|v| v.split(',')).map(str::trim).collect();

        let chunked = if !values("transfer-encoding").is_empty() {
            if !content_lengths.is_empty() {
                return Err(reject(400, "both Transfer-Encoding and Content-Length present"));
            }

            if version == HttpVersion::Http10 {
                return Err(reject(400, "Transfer-Encoding in an HTTP/1.0 request"));
            }

            if transfer_codings.last().map(String::as_str) != Some("chunked") || transfer_codings.iter().filter(|c| *c == "chunked").count() != 1 {
                return Err(reject(400, "chunked must be the final transfer coding, applied once"));
            }

            if transfer_codings.len() > 1 {
                return Err(reject(501, format!("unsupported transfer coding {}", transfer_codings[0])));
            }

            true
        } else {
            false
        };

        let content_length = if content_lengths.is_empty() {
            0
        } else {
            if content_lengths.iter().any(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit())) {
                return Err(reject(400, "invalid Content-Length"));
            }

            if content_lengths.iter().any(|v| *v != content_lengths[0]) {
                return Err(reject(400, "conflicting Content-Length values"));
            }

            let length: u64 = content_lengths[0].parse().map_err(|_| reject(413, "Content-Length too large"))?;
            if length > limits.max_body_size as u64 {
                return Err(reject(413, format!("request body of {} bytes exceeds the limit", length)));
            }

            length as usize
        };

        let expectations = values("expect");
        if version == HttpVersion::Http11 && !expectations.is_empty() {
            if expectations.iter().any(|e| !e.eq_ignore_ascii_case("100-continue")) {
                return Err(reject(417, format!("unsupported expectation {}", expectations.join(", "))));
            }

            if chunked || content_length > 0 {
                writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                writer.flush()?;
            }
        }

        let body = if chunked {
            let decoder = ChunkedDecoder::with_limits(&mut *reader, limits.max_body_size, DEFAULT_MAX_CHUNK_LINE, limits.max_header_bytes);
            decoder.decode().map_err(|e| match ChunkedLimitError::from_io(&e) {
                Some(ChunkedLimitError::BodyTooLarge { .. }) => reject(413, e.to_string()),
                Some(ChunkedLimitError::TrailersTooLarge { .. }) => reject(431, e.to_string()),
                Some(ChunkedLimitError::LineTooLong { .. }) => reject(400, e.to_string()),
                None if e.kind() == io::ErrorKind::InvalidData => reject(400, format!("malformed chunked body: {}", e)),
                None => e.into(),
            })?
        } else {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            body
        };

        Ok(Http1RawRequest {
            method,
            target: target.to_string(),
            version,
            fields,
            body,
        })
    }

    fn finalize_response_for_request(request: &HttpRequest, mut response: HttpResponse, config: &HttpServerCfg) -> io::Result<HttpResponse> {
        let method = request.method();
        let is_get_or_head = matches!(method, HttpMethod::GET | HttpMethod::HEAD);
        let range_requested = method == HttpMethod::GET && request.headers().contains("range");

        if !Self::is_bodyless_status(response.status_code()) && !response.has_header("Content-Type") {
            response.set_header("Content-Type", "application/octet-stream");
        }

        if !response.body().is_empty() && !response.has_header("Content-Encoding") && !range_requested && !Self::is_bodyless_status(response.status_code()) {
            let cfg = CompressionConfig::default();
            let content_type = response.header("Content-Type").cloned().unwrap_or_else(|| "application/octet-stream".to_string());
            if cfg.enabled && cfg.should_compress_size(response.body().len()) && cfg.should_compress_content_type(&content_type) {
                let chosen = match request.accept_encoding() {
                    Some(accept_encoding) => cfg.negotiate_algorithm(accept_encoding),
                    None => Some(CompressionAlgorithm::Identity),
                };

                if let Some(algo) = chosen.filter(|a| *a != CompressionAlgorithm::Identity) {
                    let compressed = compression::compress(algo, response.body(), cfg.level)?;
                    response.set_body(compressed);
                    response.set_header("Content-Encoding", algo.content_encoding());
                    if let Some(etag) = response.header("ETag").and_then(|v| EntityTag::parse(v)).filter(|t| !t.weak) {
                        response.set_header("ETag", etag.into_weak().to_string());
                    }
                }
            }
        }

        let status = response.status_code();
        if config.auto_etag && is_get_or_head && status == 200 && !response.has_header("ETag") {
            let etag = EntityTag::from_content(response.body());
            response.set_header("ETag", etag.to_string());
        }

        let etag = response.header("ETag").and_then(|v| EntityTag::parse(v));
        let last_modified = response.header("Last-Modified").and_then(|v| parse_http_date(v));
        if is_get_or_head && (200..300).contains(&status) {
            match evaluate_preconditions(method, request.headers(), etag.as_ref(), last_modified) {
                PreconditionOutcome::NotModified => response = Self::not_modified_response(response),
                PreconditionOutcome::PreconditionFailed => response = Self::error_response(412, "Precondition Failed"),
                PreconditionOutcome::Proceed => {}
            }
        }

        if is_get_or_head && response.status_code() == 200 {
            if !response.has_header("Accept-Ranges") {
                response.set_header("Accept-Ranges", "bytes");
            }

            if range_requested {
                response = Self::apply_range(request, response, etag.as_ref(), last_modified)?;
            }
        }

        if !response.has_header("Date") {
            response.set_header("Date", http_date_now());
        }

        if Self::is_bodyless_status(response.status_code()) {
            response.set_body(Vec::new());
            response.remove_header("Content-Length");
            response.remove_header("Digest");
            response.remove_header("X-Content-SHA256");
        } else {
            let body_len = response.body().len();
            let digest = sha256(response.body());
            response.set_header("Content-Length", body_len.to_string());
            response.set_header("Digest", format!("SHA-256={}", pem::encode(&digest)));
            response.set_header("X-Content-SHA256", Self::to_hex(&digest));
        }

        Ok(response)
    }

    fn apply_range(request: &HttpRequest, response: HttpResponse, etag: Option<&EntityTag>, last_modified: Option<u64>) -> io::Result<HttpResponse> {
        if response.header("Accept-Ranges").map(|v| v.eq_ignore_ascii_case("none")).unwrap_or(false) {
            return Ok(response);
        }

        if let Some(if_range) = request.headers().get("if-range") {
            if !if_range_matches(if_range, etag, last_modified) {
                return Ok(response);
            }
        }

        let Some(specs) = request.headers().get("range").and_then(|v| parse_range_header(v).ok()) else {
            return Ok(response);
        };

        let complete_length = response.body().len() as u64;
        match evaluate_ranges(&specs, complete_length) {
            RangeOutcome::NotSatisfiable => {
                let mut unsatisfiable = Self::error_response(416, "Range Not Satisfiable");
                unsatisfiable.set_header("Content-Range", ContentRange::Unsatisfied { complete_length }.to_string());
                Ok(unsatisfiable)
            }
            RangeOutcome::Partial(ranges) if ranges.len() == 1 => {
                let range = ranges[0];
                let mut partial = response;
                let body = range.slice(partial.body()).to_vec();
                partial.set_status(206, "Partial Content");
                partial.set_header("Content-Range", ContentRange::Bytes { range, complete_length: Some(complete_length) }.to_string());
                partial.set_body(body);
                Ok(partial)
            }
            RangeOutcome::Partial(ranges) => {
                let boundary = random::generate_random(12)
                    .map(|bytes| Self::to_hex(&bytes))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to generate multipart boundary: {}", e)))?;
                let mut partial = response;
                let content_type = partial.header("Content-Type").cloned();
                let body = build_multipart_byteranges(partial.body(), &ranges, content_type.as_deref(), &boundary);
                partial.set_status(206, "Partial Content");
                partial.set_header("Content-Type", format!("multipart/byteranges; boundary={}", boundary));
                partial.set_body(body);
                Ok(partial)
            }
        }
    }

    fn not_modified_response(response: HttpResponse) -> HttpResponse {
        const REPRESENTATION_FIELDS: [&str; 9] = [
            "content-type", "content-length", "content-encoding", "content-language", "content-range",
            "transfer-encoding", "digest", "x-content-sha256", "accept-ranges",
        ];

        let fields = response.header_fields().iter()
            .filter(|(name, _)| !REPRESENTATION_FIELDS.iter().any(|f| name.eq_ignore_ascii_case(f)))
            .cloned()
            .collect();
        HttpResponse::with_fields(304, "Not Modified".to_string(), response.version(), fields, Vec::new())
    }

    fn is_bodyless_status(status: u16) -> bool {
        (100..200).contains(&status) || status == 204 || status == 304
    }

    fn serialize_response(response: &HttpResponse, head_request: bool) -> Vec<u8> {
        let mut result = Vec::new();
        let status_line = format!(
            "{} {} {}\r\n",
            response.version().as_str(),
            response.status_code(),
            response.reason_phrase()
        );

        result.extend_from_slice(status_line.as_bytes());
        for (key, value) in response.header_fields() {
            result.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        if !response.has_header("Content-Length") && !response.body().is_empty() {
            result.extend_from_slice(
                format!("Content-Length: {}\r\n", response.body().len()).as_bytes(),
            );
        }

        result.extend_from_slice(b"\r\n");
        if !head_request {
            result.extend_from_slice(response.body());
        }

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
                headers.insert("Date".to_string(), http_date_now());
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

impl Http1RawRequest {
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.fields.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }
}

impl Http1RequestLimits {
    pub fn from_cfg(cfg: &HttpServerCfg) -> Self {
        Self {
            max_request_line_size: cfg.max_request_line_size,
            max_header_bytes: cfg.max_header_bytes,
            max_header_count: cfg.max_header_count,
            max_body_size: cfg.max_body_size,
        }
    }
}

impl Default for Http1RequestLimits {
    fn default() -> Self {
        Self::from_cfg(&HttpServerCfg::default())
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

    lines.push(format!("max-request-line-size={}", server.cfg.max_request_line_size));
    lines.push(format!("max-header-bytes={}", server.cfg.max_header_bytes));
    lines.push(format!("max-header-count={}", server.cfg.max_header_count));
    lines.push(format!("auto-etag={}", server.cfg.auto_etag));
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
            "max-request-line-size" | "max-header-bytes" | "max-header-count" => {
                let parsed = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", key))
                })?;

                match key {
                    "max-request-line-size" => cfg.max_request_line_size = parsed,
                    "max-header-bytes" => cfg.max_header_bytes = parsed,
                    _ => cfg.max_header_count = parsed,
                }
            }
            "auto-etag" => {
                cfg.auto_etag = parse_bool(value.trim())?;
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

fn reject(status: u16, reason: impl Into<String>) -> Http1ReadError {
    Http1ReadError::Reject(status, reason.into())
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if available.is_empty() {
            return if line.is_empty() {
                Ok(Line::Eof)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed mid-line"))
            };
        }

        let (taken, done) = match available.iter().position(|&b| b == b'\n') {
            Some(newline) => (newline + 1, true),
            None => (available.len(), false),
        };

        if line.len() + taken > max + 2 {
            return Ok(Line::TooLong);
        }

        line.extend_from_slice(&available[..taken]);
        reader.consume(taken);
        if done {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }

            return if line.len() > max { Ok(Line::TooLong) } else { Ok(Line::Bytes(line)) };
        }
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_valid_host(value: &str) -> bool {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let Some(close) = rest.find(']') else { return false };
        let literal = &rest[..close];
        if literal.is_empty() || !literal.bytes().all(|b| b.is_ascii_hexdigit() || b":.vV".contains(&b)) {
            return false;
        }

        match &rest[close + 1..] {
            "" => (literal, None),
            after => match after.strip_prefix(':') {
                Some(port) => (literal, Some(port)),
                None => return false,
            },
        }
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        }
    };

    if let Some(port) = port {
        if !port.bytes().all(|b| b.is_ascii_digit()) || port.len() > 5 {
            return false;
        }
    }

    if value.starts_with('[') {
        return true;
    }

    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() || !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                    return false;
                }

                i += 3;
                continue;
            }
            b if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b) => {}
            _ => return false,
        }

        i += 1;
    }

    true
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
            max_request_line_size: 8 * 1024,
            max_header_bytes: 64 * 1024,
            max_header_count: 100,
            auto_etag: true,
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

impl From<io::Error> for Http1ReadError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Http1ReadError::Reject(408, "request timed out".to_string()),
            _ => Http1ReadError::Io(err),
        }
    }
}

impl std::fmt::Display for Http1ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Http1ReadError::Closed => write!(f, "connection closed"),
            Http1ReadError::Reject(status, reason) => write!(f, "{}: {}", status, reason),
            Http1ReadError::Io(e) => write!(f, "{}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const BODY: &[u8] = b"0123456789abcdefghij";

    struct Wire {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Wire {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }

        fn header_values(&self, name: &str) -> Vec<&str> {
            self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
        }
    }

    fn echo_handler() -> HttpHandler {
        Arc::new(|request: &HttpRequest| {
            let body = if request.body_bytes().is_empty() { BODY.to_vec() } else { request.body_bytes().to_vec() };
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/plain".to_string());
            HttpResponse::new(200, "OK".to_string(), HttpVersion::Http11, headers, body)
        })
    }

    fn exchange_with(cfg: &HttpServerCfg, handler: HttpHandler, raw: &[u8]) -> Vec<u8> {
        let mut reader = Cursor::new(raw.to_vec());
        let mut writer = Vec::new();
        HttpServer::serve_connection(&mut reader, &mut writer, cfg, Some(&handler)).unwrap();
        writer
    }

    fn exchange(raw: &[u8]) -> Vec<Wire> {
        parse_wire(&exchange_with(&HttpServerCfg::default(), echo_handler(), raw), false)
    }

    fn parse_wire(mut data: &[u8], head: bool) -> Vec<Wire> {
        let mut responses = Vec::new();
        while !data.is_empty() {
            let end = data.windows(4).position(|w| w == b"\r\n\r\n").expect("response head terminator");
            let head_text = std::str::from_utf8(&data[..end]).unwrap();
            let mut lines = head_text.split("\r\n");
            let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse::<u16>().unwrap();
            let headers: Vec<(String, String)> = lines.map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.trim().to_string(), v.trim().to_string())
            }).collect();
            data = &data[end + 4..];

            let mut wire = Wire { status, headers, body: Vec::new() };
            let len = if head || HttpServer::is_bodyless_status(status) {
                0
            } else {
                wire.header("content-length").map(|v| v.parse().unwrap()).unwrap_or(0)
            };

            wire.body = data[..len].to_vec();
            data = &data[len..];
            responses.push(wire);
        }

        responses
    }

    fn get(extra_headers: &str) -> Vec<u8> {
        format!("GET /file HTTP/1.1\r\nHost: example.com\r\n{}\r\n", extra_headers).into_bytes()
    }

    #[test]
    fn test_host_header_is_required_and_validated() {
        assert_eq!(exchange(b"GET / HTTP/1.1\r\n\r\n")[0].status, 400);
        assert_eq!(exchange(b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n")[0].status, 400);
        for bad in ["exa mple.com", "a/b", "example.com:80x", "[::1", "[zz]:80", "%zz", "a@b"] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", bad);
            assert_eq!(exchange(raw.as_bytes())[0].status, 400, "Host: {}", bad);
        }

        for good in ["example.com", "example.com:8080", "127.0.0.1", "[::1]:443", "xn--bcher-kva.example", ""] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", good);
            assert_eq!(exchange(raw.as_bytes())[0].status, 200, "Host: {}", good);
        }

        assert_eq!(exchange(b"GET / HTTP/1.0\r\n\r\n")[0].status, 200);
        assert_eq!(exchange(b"GET / HTTP/1.0\r\nHost: a\r\nHost: a\r\n\r\n")[0].status, 400);
    }

    #[test]
    fn test_request_line_and_header_limits() {
        let cfg = HttpServerCfg { max_request_line_size: 64, max_header_bytes: 128, max_header_count: 4, ..HttpServerCfg::default() };
        let send = |raw: String| parse_wire(&exchange_with(&cfg, echo_handler(), raw.as_bytes()), false)[0].status;

        assert_eq!(send(format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "x".repeat(100))), 414);
        assert_eq!(send(format!("GET / HTTP/1.1\r\nHost: a\r\nX-Big: {}\r\n\r\n", "x".repeat(200))), 431);
        assert_eq!(send("GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n".to_string()), 431);
        assert_eq!(send("GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nConnection: close\r\n\r\n".to_string()), 200);

        let endless = format!("GET /{}", "x".repeat(10_000));
        assert_eq!(send(endless), 414);
    }

    #[test]
    fn test_malformed_request_lines_and_fields() {
        assert_eq!(exchange(b"BREW / HTTP/1.1\r\nHost: a\r\n\r\n")[0].status, 501);
        assert_eq!(exchange(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n")[0].status, 505);
        assert_eq!(exchange(b"GET / HTTX/1.1\r\nHost: a\r\n\r\n")[0].status, 400);
        assert_eq!(exchange(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n")[0].status, 400);
        assert_eq!(exchange(b"GET / HTTP/1.1\r\nHost: a\r\nX-Folded: a\r\n  b\r\n\r\n")[0].status, 400);
        assert_eq!(exchange(b"GET / HTTP/1.1\r\nHost: a\r\nX-Bad : a\r\n\r\n")[0].status, 400);
        assert_eq!(exchange(b"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n")[0].status, 400);
    }

    #[test]
    fn test_chunked_request_body_and_pipelined_follow_up() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        let responses = exchange(raw);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].status, 200);
        assert_eq!(responses[0].body, b"hello world");
        assert_eq!(responses[1].status, 200);
        assert_eq!(responses[1].body, BODY);
    }

    #[test]
    fn test_request_smuggling_framing_is_rejected() {
        let cases: [(&[u8], u16); 7] = [
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501),
            (b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello", 400),
        ];

        for (raw, status) in cases {
            let responses = exchange(raw);
            assert_eq!(responses.len(), 1, "{}", String::from_utf8_lossy(raw));
            assert_eq!(responses[0].status, status, "{}", String::from_utf8_lossy(raw));
            assert_eq!(responses[0].header("connection"), Some("close"));
        }

        let same = exchange(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\nConnection: close\r\n\r\nhello");
        assert_eq!(same[0].status, 200);
        assert_eq!(same[0].body, b"hello");
    }

    #[test]
    fn test_chunked_body_limit_returns_413() {
        let cfg = HttpServerCfg { max_body_size: 8, ..HttpServerCfg::default() };
        let raw = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
        assert_eq!(parse_wire(&exchange_with(&cfg, echo_handler(), raw), false)[0].status, 413);

        let raw = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 9\r\n\r\n123456789";
        assert_eq!(parse_wire(&exchange_with(&cfg, echo_handler(), raw), false)[0].status, 413);
    }

    #[test]
    fn test_expect_100_continue() {
        let raw = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nhello";
        let wire = exchange_with(&HttpServerCfg::default(), echo_handler(), raw);
        assert!(wire.starts_with(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        let responses = parse_wire(&wire, false);
        assert_eq!(responses[1].body, b"hello");

        let cfg = HttpServerCfg { max_body_size: 4, ..HttpServerCfg::default() };
        let wire = exchange_with(&cfg, echo_handler(), b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        assert!(wire.starts_with(b"HTTP/1.1 413 "));

        assert_eq!(exchange(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nExpect: teapot\r\n\r\nx")[0].status, 417);

        let wire = exchange_with(&HttpServerCfg::default(), echo_handler(), b"POST / HTTP/1.0\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi");
        assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_repeated_response_headers_are_all_sent() {
        let handler: HttpHandler = Arc::new(|_: &HttpRequest| {
            let mut response = HttpResponse::new(200, "OK".to_string(), HttpVersion::Http11, HashMap::new(), b"ok".to_vec());
            response.append_header("Set-Cookie", "a=1; Path=/");
            response.append_header("Set-Cookie", "b=2; Path=/");
            response.append_header("Vary", "Accept");
            response.append_header("Vary", "Accept-Language");
            response
        });

        let responses = parse_wire(&exchange_with(&HttpServerCfg::default(), handler, &get("Connection: close\r\n")), false);
        assert_eq!(responses[0].header_values("set-cookie"), vec!["a=1; Path=/", "b=2; Path=/"]);
        assert_eq!(responses[0].header_values("vary"), vec!["Accept", "Accept-Language"]);
    }

    #[test]
    fn test_conditional_get_with_auto_etag() {
        let first = exchange(&get("Connection: close\r\n"));
        let etag = first[0].header("etag").unwrap().to_string();
        assert!(etag.starts_with('"'));

        let not_modified = exchange(&get(&format!("If-None-Match: {}\r\nConnection: close\r\n", etag)));
        assert_eq!(not_modified[0].status, 304);
        assert!(not_modified[0].body.is_empty());
        assert_eq!(not_modified[0].header("etag"), Some(etag.as_str()));
        assert_eq!(not_modified[0].header("content-length"), None);

        let changed = exchange(&get("If-None-Match: \"stale\"\r\nConnection: close\r\n"));
        assert_eq!(changed[0].status, 200);

        let failed = exchange(&get("If-Match: \"stale\"\r\nConnection: close\r\n"));
        assert_eq!(failed[0].status, 412);
    }

    #[test]
    fn test_if_modified_since_against_handler_last_modified() {
        let handler: HttpHandler = Arc::new(|_: &HttpRequest| {
            let mut response = HttpResponse::new(200, "OK".to_string(), HttpVersion::Http11, HashMap::new(), BODY.to_vec());
            response.set_header("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT");
            response
        });

        let cfg = HttpServerCfg { auto_etag: false, ..HttpServerCfg::default() };
        let send = |headers: &str| parse_wire(&exchange_with(&cfg, handler.clone(), &get(headers)), false).remove(0);
        assert_eq!(send("If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nConnection: close\r\n").status, 304);
        assert_eq!(send("If-Modified-Since: Sat, 05 Nov 1994 08:49:37 GMT\r\nConnection: close\r\n").status, 200);
        assert_eq!(send("If-Unmodified-Since: Sat, 05 Nov 1994 08:49:37 GMT\r\nConnection: close\r\n").status, 412);
    }

    #[test]
    fn test_single_range_request() {
        let responses = exchange(&get("Range: bytes=2-5\r\nConnection: close\r\n"));
        assert_eq!(responses[0].status, 206);
        assert_eq!(responses[0].body, b"2345");
        assert_eq!(responses[0].header("content-range"), Some("bytes 2-5/20"));
        assert_eq!(responses[0].header("content-length"), Some("4"));

        let suffix = exchange(&get("Range: bytes=-3\r\nConnection: close\r\n"));
        assert_eq!(suffix[0].body, b"hij");

        let full = exchange(&get("Connection: close\r\n"));
        assert_eq!(full[0].status, 200);
        assert_eq!(full[0].header("accept-ranges"), Some("bytes"));
    }

    #[test]
    fn test_multi_range_request_is_multipart() {
        let responses = exchange(&get("Range: bytes=0-1, 10-11\r\nConnection: close\r\n"));
        assert_eq!(responses[0].status, 206);
        let content_type = responses[0].header("content-type").unwrap();
        let boundary = content_type.strip_prefix("multipart/byteranges; boundary=").unwrap();
        let parts = crate::net::http::range::parse_multipart_byteranges(&responses[0].body, boundary).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].data, b"01");
        assert_eq!(parts[1].data, b"ab");
        assert_eq!(parts[0].content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn test_unsatisfiable_and_ignored_ranges() {
        let unsatisfiable = exchange(&get("Range: bytes=50-\r\nConnection: close\r\n"));
        assert_eq!(unsatisfiable[0].status, 416);
        assert_eq!(unsatisfiable[0].header("content-range"), Some("bytes */20"));

        for ignored in ["Range: items=0-1", "Range: bytes=5-1", "Range: bytes=0-1\r\nIf-Range: \"stale\""] {
            let responses = exchange(&get(&format!("{}\r\nConnection: close\r\n", ignored)));
            assert_eq!(responses[0].status, 200, "{}", ignored);
            assert_eq!(responses[0].body, BODY);
        }

        let etag = exchange(&get("Connection: close\r\n"))[0].header("etag").unwrap().to_string();
        let honoured = exchange(&get(&format!("Range: bytes=0-1\r\nIf-Range: {}\r\nConnection: close\r\n", etag)));
        assert_eq!(honoured[0].status, 206);

        let post = exchange(b"POST / HTTP/1.1\r\nHost: a\r\nRange: bytes=0-1\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
        assert_eq!(post[0].status, 200);
    }

    #[test]
    fn test_head_response_has_length_but_no_body() {
        let wire = exchange_with(&HttpServerCfg::default(), echo_handler(), b"HEAD /file HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        let responses = parse_wire(&wire, true);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].header("content-length"), Some("20"));
        assert!(wire.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn test_keep_alive_and_http10_connection_handling() {
        let responses = exchange(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(responses.len(), 2);

        let http10 = exchange(b"GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.0\r\n\r\n");
        assert_eq!(http10.len(), 1);
        assert_eq!(http10[0].header("connection"), Some("close"));

        let http10_keep_alive = exchange(b"GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.0\r\n\r\n");
        assert_eq!(http10_keep_alive.len(), 2);
        assert_eq!(http10_keep_alive[0].header("connection"), Some("keep-alive"));
        assert_eq!(http10_keep_alive[1].header("connection"), Some("close"));
    }

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