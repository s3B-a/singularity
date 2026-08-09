use super::auth::{AuthChallenge, Authenticator, Credentials};
use super::http2::Http2Connection;
use super::http3::Config as Http3Config;
use super::http3_client::Http3Client;
use super::method::HttpMethod;
use super::request::HttpRequest;
use super::response::HttpResponse;
use super::version::HttpVersion;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::connection_pool::{ConnectionPool, PooledProtocol};
use crate::net::cookie::{parse_set_cookie, Cookie, CookieJar};
use crate::net::dns::DnsResolver;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::tcp::TcpStream;
use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HTTP_CLIENT_PROFILE_BLOB_MAGIC: &str = "SINGULARITY_HTTP_CLIENT_PROFILE_BLOB_V1";
const HTTP_CLIENT_PROFILE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_CLIENT_PROFILE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpClientProfileMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
struct StreamInfo {
    stream_id: u32,
    created_at: Instant,
    request_url: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub connection_key: String,
    pub active_streams: usize,
    pub max_concurrent_streams: usize,
    pub last_used: Instant,
    pub age: Duration,
    pub is_http2: bool,
    pub requests_made: usize,
}

#[derive(Clone)]
struct CachedChallenge {
    challenge: AuthChallenge,
    cached_at: Instant,
    url_pattern: String,
}

#[derive(Clone)]
struct PipelinedRequest {
    request: HttpRequest,
    request_id: u64,
    sent_at: Instant,
}

struct Http1ConnectionEntry {
    stream: TcpStream,
    host: String,
    port: u16,
    last_used: Instant,
    requests_made: usize,
    max_requests: usize,
    created_at: Instant,
    idle_timeout: Duration,
    supports_pipelining: bool,
    pending_requests: usize,
    pipeline_queue: VecDeque<PipelinedRequest>,
    pipeline_depth: usize,
    max_pipeline_depth: usize,
    response_buffer: Vec<u8>,
}

impl Http1ConnectionEntry {
    fn new(stream: TcpStream, host: String, port: u16) -> Self {
        Self {
            stream,
            host,
            port,
            last_used: Instant::now(),
            requests_made: 0,
            max_requests: 100,
            created_at: Instant::now(),
            idle_timeout: Duration::from_secs(30),
            supports_pipelining: false,
            pending_requests: 0,
            pipeline_queue: VecDeque::new(),
            pipeline_depth: 0,
            max_pipeline_depth: 6,
            response_buffer: Vec::new(),
        }
    }

    fn is_stale(&self, timeout: Duration) -> bool {
        self.last_used.elapsed() > timeout
    }

    fn should_close(&self) -> bool {
        self.requests_made >= self.max_requests
    }

    fn is_idle_timeout(&self) -> bool {
        self.last_used.elapsed() > self.idle_timeout
    }

    fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.requests_made += 1;
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn can_pipeline(&self) -> bool {
        self.supports_pipelining && self.pipeline_depth < self.max_pipeline_depth
    }

    fn enqueue_request(&mut self, request: HttpRequest, request_id: u64) -> Result<(), io::Error> {
        if !self.can_pipeline() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Pipeline is full"
            ));
        }

        let pipelined = PipelinedRequest {
            request,
            request_id,
            sent_at: Instant::now(),
        };

        self.pipeline_queue.push_back(pipelined);
        self.pipeline_depth += 1;
        self.pending_requests += 1;

        Ok(())
    }

    fn send_pipelined_request(&mut self) -> Result<(), io::Error> {
        while let Some(pipelined) = self.pipeline_queue.front() {
            let request_bytes = pipelined.request.build(&self.host);
            match self.stream.write_all(&request_bytes) {
                Ok(_) => {
                    self.stream.flush()?;
                    self.pipeline_queue.pop_front();
                    self.requests_made += 1;
                    self.mark_used();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(());
                }
                Err(e) => return Err(e)
            }
        }

        Ok(())
    }

    fn read_pipelined_response(&mut self, timeout: Duration) -> Result<Option<HttpResponse>, io::Error> {
        if self.pending_requests == 0 {
            return Ok(None);
        }

        self.stream.set_read_timeout(Some(timeout))?;
        let mut temp_buffer = vec![0u8; 8192];

        let start = Instant::now();
        loop {
            match self.stream.read(&mut temp_buffer) {
                Ok(n) if n > 0 => {
                    self.response_buffer.extend_from_slice(&temp_buffer[..n]);
                    if let Ok(Some(response)) = self.try_parse_response() {
                        self.pending_requests -= 1;
                        self.pipeline_depth = self.pipeline_depth.saturating_sub(1);
                        return Ok(Some(response));
                    }
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Connection closed by peer"
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    if !self.response_buffer.is_empty() {
                        if let Ok(Some(response)) = self.try_parse_response() {
                            self.pending_requests -= 1;
                            self.pipeline_depth = self.pipeline_depth.saturating_sub(1);
                            return Ok(Some(response));
                        }
                    }
                    
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn try_parse_response(&mut self) -> Result<Option<HttpResponse>, io::Error> {
        if self.response_buffer.len() < 4 {
            return Ok(None);
        }

        let header_end = self.response_buffer.windows(4).position(|w| w == b"\r\n\r\n");
        let header_end = match header_end {
            Some(pos) => pos,
            None => {
                if self.response_buffer.len() > 65536 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Response headers too large",
                    ));
                }

                return Ok(None);
            }
        };

        let header_section = &self.response_buffer[..header_end];
        let header_str = std::str::from_utf8(header_section).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in headers")
        })?;

        let content_length = self.extract_content_length(header_str);
        let is_chunked = self.is_chunked_encoding(header_str);
        let body_start = header_end + 4;
        if is_chunked {
            if let Some(body_end) = self.find_chunked_end(body_start) {
                let response_bytes = self.response_buffer.drain(..body_end).collect::<Vec<_>>();
                return Ok(Some(
                    HttpResponse::from_bytes(&response_bytes)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                ));
            }

            return Ok(None);
        }

        if let Some(len) = content_length {
            let body_end = body_start + len;
            if self.response_buffer.len() >= body_end {
                let response_bytes = self.response_buffer.drain(..body_end).collect::<Vec<_>>();
                return Ok(Some(
                    HttpResponse::from_bytes(&response_bytes)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                ));
            }

            return Ok(None);
        }

        let response_bytes = self.response_buffer.drain(..).collect::<Vec<_>>();

        Ok(Some(
            HttpResponse::from_bytes(&response_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        ))
    }

    fn extract_content_length(&self, headers: &str) -> Option<usize> {
        for line in headers.lines() {
            if line.to_lowercase().starts_with("content-length:") {
                if let Some(value) = line.split(':').nth(1) {
                    return value.trim().parse().ok();
                }
            }
        }

        None
    }

    fn is_chunked_encoding(&self, headers: &str) -> bool {
        for line in headers.lines() {
            if line.to_lowercase().starts_with("transfer-encoding:") {
                if let Some(value) = line.split(':').nth(1) {
                    return value.to_lowercase().contains("chunked");
                }
            }
        }

        false
    }

    fn find_chunked_end(&self, start: usize) -> Option<usize> {
        let data = &self.response_buffer[start..];
        let mut pos = 0;
        loop {
            let size_line_end = data[pos..].iter().position(|&b| b == b'\n').map(|p| pos + p)?;

            let size_line = &data[pos..size_line_end];
            let size_str = std::str::from_utf8(size_line).ok()?.trim_end_matches('\r').split(';').next()?.trim();
            let chunk_size = usize::from_str_radix(size_str, 16).ok()?;
            if chunk_size == 0 {
                let after_zero = size_line_end + 1;
                let mut trailer_end = after_zero;
                loop {
                    if trailer_end + 1 >= data.len() {
                        return None;
                    }

                    if data[trailer_end] == b'\r' && data[trailer_end + 1] == b'\n' {
                        return Some(start + trailer_end + 2);
                    }

                    trailer_end = data[trailer_end..].iter().position(|&b| b == b'\n').map(|p| trailer_end + p + 1)?;
                }
            }

            pos = size_line_end + 1 + chunk_size + 2;
            if pos > data.len() {
                return None;
            }
        }
    }

    fn detect_pipelining_support(&mut self, response: &HttpResponse) {
        if let Some(connection) = response.header("Connection") {
            if connection.to_lowercase() == "close" {
                self.supports_pipelining = false;
                self.max_pipeline_depth = 1;
            }
        }

        if response.version() == HttpVersion::Http10 {
            self.supports_pipelining = false;
            self.max_pipeline_depth = 1;
        }
    }

    fn flush_pipeline(&mut self, timeout: Duration) -> Result<Vec<HttpResponse>, io::Error> {
        while self.pipeline_queue.front().is_some() {
            self.send_pipelined_request()?;
        }

        let mut responses = Vec::new();
        let deadline = Instant::now() + timeout;
        while self.pending_requests > 0 {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Pipeline flush timeout",
                ));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let read_timeout = remaining.min(Duration::from_millis(100));
            match self.read_pipelined_response(read_timeout) {
                Ok(Some(response)) => {
                    self.detect_pipelining_support(&response);
                    responses.push(response);
                }
                Ok(None) => {
                    if self.pending_requests > 0 {
                        continue;
                    } else {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(responses)
    }

    fn is_healthy(&mut self) -> bool {
        let mut buf = [0u8; 1];
        match self.stream.peek(&mut buf) {
            Ok(0) => false,
            Ok(_) => true,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    }
}

struct Http2ConnectionEntry {
    connection: Http2Connection,
    host: String,
    port: u16,
    last_used: Instant,
    active_streams: HashMap<u32, StreamInfo>,
    next_stream_id: u32,
    max_concurrent_streams: usize,
}

impl Http2ConnectionEntry {
    fn new(connection: Http2Connection, host: String, port: u16) -> Self {
        Self {
            connection,
            host,
            port,
            last_used: Instant::now(),
            active_streams: HashMap::new(),
            next_stream_id: 1,
            max_concurrent_streams: 100,
        }
    }

    fn can_create_stream(&self) -> bool {
        self.active_streams.len() < self.max_concurrent_streams
    }

    fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    fn create_tracked_stream(&mut self, request_url: String) -> Result<u32, io::Error> {
        if !self.can_create_stream() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Maximum concurrent streams reached",
            ));
        }

        let stream_id = self.connection.create_stream().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create stream: {:?}", e),
            )
        })?;

        self.active_streams.insert(
            stream_id,
            StreamInfo {
                stream_id,
                created_at: Instant::now(),
                request_url,
            },
        );

        self.next_stream_id += 2;
        self.last_used = Instant::now();

        Ok(stream_id)
    }

    fn remove_stream(&mut self, stream_id: u32) {
        self.active_streams.remove(&stream_id);
    }

    fn cleanup_finished_streams(&mut self) -> Result<(), io::Error> {
        let mut finished_streams = Vec::new();
        for &stream_id in self.active_streams.keys() {
            if let Some(stream) = self.connection.get_stream(stream_id) {
                if stream.is_closed() {
                    finished_streams.push(stream_id);
                }
            }
        }

        for stream_id in finished_streams {
            self.remove_stream(stream_id);
        }

        Ok(())
    }

    fn update_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams = max as usize;
    }

    pub fn process_frames(&mut self) -> Result<(), io::Error> {
        self.connection.receive_frames().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to process frames: {:?}", e),
            )
        })?;

        self.cleanup_finished_streams()?;

        Ok(())
    }

    pub fn receive_response(&mut self, stream_id: u32) -> Result<(HashMap<String, String>, Vec<u8>), io::Error> {
        let stream = self.connection.get_stream_mut(stream_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("Stream {} not found", stream_id))
        })?;

        let headers_vec = stream.response_headers();
        let mut headers = HashMap::new();
        for (key, value) in headers_vec {
            headers.insert(key.clone(), value.clone());
        }

        let body = stream.take_received_data();
        self.last_used = Instant::now();
        self.remove_stream(stream_id);

        Ok((headers, body))
    }

    fn receive_response_with_timeout(&mut self, stream_id: u32, timeout: Duration) -> Result<(HashMap<String, String>, Vec<u8>), io::Error> {
        let start = Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Response timeout for stream {}", stream_id),
                ));
            }

            let stream = self.connection.get_stream(stream_id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("Stream {} not found", stream_id))
            })?;

            if stream.is_closed() {
                return self.receive_response(stream_id);
            }

            match self.process_frames() {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    return Err(e);
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn poll_responses(&mut self) -> Result<Vec<(u32, HashMap<String, String>, Vec<u8>)>, io::Error> {
        let mut completed = Vec::new();
        let stream_ids: Vec<u32> = self.active_streams.keys().copied().collect();

        let _ = self.process_frames();
        for stream_id in stream_ids {
            if let Some(stream) = self.connection.get_stream(stream_id) {
                if stream.is_closed() {
                    match self.receive_response(stream_id) {
                        Ok((headers, body)) => {
                            completed.push((stream_id, headers, body));
                        }
                        Err(e) => {
                            eprintln!("Error receiving response for stream {}: {:?}", stream_id, e);
                            self.remove_stream(stream_id);
                        }
                    }
                }
            }
        }

        Ok(completed)
    }
}

pub struct HttpClientBuilder {
    client: HttpClient,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.client.timeout = Some(timeout);
        self
    }

    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.client.user_agent = user_agent;
        self
    }

    pub fn default_header(mut self, key: String, value: String) -> Self {
        self.client.default_headers.insert(key, value);
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.client.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.client.max_redirects = max;
        self
    }

    pub fn preferred_version(mut self, version: HttpVersion) -> Self {
        self.client.preferred_version = version;
        self
    }

    pub fn enable_cookies(mut self, enable: bool) -> Self {
        self.client.enable_cookies = enable;
        self
    }

    pub fn enable_version_negotiation(mut self, enable: bool) -> Self {
        self.client.enable_version_negotiation = enable;
        self
    }

    pub fn enable_http3(mut self, enable: bool) -> Self {
        self.client.enable_http3 = enable;
        if enable && self.client.http3_client.is_none() {
            self.client.http3_client = Some(Http3Client::new());
        }

        self
    }

    pub fn http3_config(mut self, config: Http3Config) -> Self {
        self.client.http3_client = Some(Http3Client::with_config(config));
        self.client.enable_http3 = true;

        self
    }

    pub fn http3_timeout(mut self, timeout: Duration) -> Self {
        if let Some(ref mut client) = self.client.http3_client {
            *client = std::mem::take(client).with_timeout(timeout);
        } else {
            self.client.http3_client = Some(Http3Client::new().with_timeout(timeout));
        }

        self.client.enable_http3 = true;
        self
    }

    pub fn build(self) -> HttpClient {
        self.client
    }

    pub fn accept(mut self, media_types: Vec<String>) -> Self {
        self.client.default_headers.insert("Accept".to_string(), media_types.join(", "));
        self
    }

    pub fn accept_language(mut self, languages: Vec<String>) -> Self {
        self.client.default_headers.insert("Accept-Language".to_string(), languages.join(", "));
        self
    }

    pub fn accept_encoding(mut self, encodings: Vec<String>) -> Self {
        self.client.default_headers.insert("Accept-Encoding".to_string(), encodings.join(", "));
        self
    }

    pub fn accept_charset(mut self, charsets: Vec<String>) -> Self {
        self.client.default_headers.insert("Accept-Charset".to_string(), charsets.join(", "));
        self
    }

    pub fn connection_pool_cfg(mut self, max_idle: usize, idle_timeout: Duration, max_age: Duration) -> Self {
        let _ = (max_idle, max_age);
        self.client.idle_timeout = idle_timeout;
        self
    }

    pub fn connection_timeout(self, timeout: Duration) -> Self {
        self.timeout(timeout)
    }

    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.client.idle_timeout = timeout;
        self
    }

    pub fn keep_alive(self, _enable: bool) -> Self {
        self
    }

    pub fn max_connections(mut self, max: usize) -> Self {
        self.client.max_connections_per_host = max;
        self
    }

    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.client.set_credentials(username, password);
        self
    }

    pub fn auto_auth(mut self, enable: bool) -> Self {
        self.client.set_auto_auth(enable);
        self
    }

    pub fn challenge_cache_ttl(mut self, ttl: Duration) -> Self {
        self.client.challenge_cache_ttl = ttl;
        self
    }

    pub fn disable_challenge_cache(mut self) -> Self {
        self.client.challenge_cache_ttl = Duration::from_secs(0);
        self
    }
}

pub struct HttpClient {
    default_headers: HashMap<String, String>,
    timeout: Option<Duration>,
    follow_redirects: bool,
    max_redirects: usize,
    user_agent: String,
    preferred_version: HttpVersion,
    http1_connections: HashMap<String, Http1ConnectionEntry>,
    http2_connections: HashMap<String, Http2ConnectionEntry>,
    max_connections_per_host: usize,
    connection_timeout: Duration,
    stream_timeout: Duration,
    idle_timeout: Duration,
    enable_pipelining: bool,
    expect_100_continue_threshold: usize,
    cookie_jar: CookieJar,
    enable_cookies: bool,
    dns_resolver: DnsResolver,
    connection_pool: ConnectionPool,
    next_request_id: u64,
    pipeline_requests: HashMap<String, VecDeque<(u64, HttpRequest)>>,
    version_cache: HashMap<String, HttpVersion>,
    alt_svc_cache: HashMap<String, Vec<(HttpVersion, String, u16)>>,
    enable_version_negotiation: bool,
    authenticator: Authenticator,
    auto_auth: bool,
    challenge_cache: HashMap<String, CachedChallenge>,
    challenge_cache_ttl: Duration,
    enable_http3: bool,
    http3_client: Option<Http3Client>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            default_headers: HashMap::new(),
            timeout: Some(Duration::from_secs(30)),
            follow_redirects: true,
            max_redirects: 10,
            user_agent: "Singularity/Beta-0.0.1".to_string(),
            preferred_version: HttpVersion::Http2,
            http1_connections: HashMap::new(),
            http2_connections: HashMap::new(),
            max_connections_per_host: 6,
            connection_timeout: Duration::from_secs(300),
            stream_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            enable_pipelining: false,
            expect_100_continue_threshold: 1024 * 1024,
            cookie_jar: CookieJar::new(),
            enable_cookies: true,
            dns_resolver: DnsResolver::new(),
            connection_pool: ConnectionPool::new(),
            next_request_id: 0,
            pipeline_requests: HashMap::new(),
            version_cache: HashMap::new(),
            alt_svc_cache: HashMap::new(),
            enable_version_negotiation: true,
            authenticator: Authenticator::new(),
            auto_auth: true,
            challenge_cache: HashMap::new(),
            challenge_cache_ttl: Duration::from_secs(300),
            enable_http3: false,
            http3_client: None,
        }
    }

    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn set_user_agent(&mut self, user_agent: String) {
        self.user_agent = user_agent;
    }

    pub fn set_default_header(&mut self, key: String, value: String) {
        self.default_headers.insert(key, value);
    }

    pub fn set_follow_redirects(&mut self, follow: bool) {
        self.follow_redirects = follow;
    }

    pub fn set_preferred_version(&mut self, version: HttpVersion) {
        self.preferred_version = version;
    }

    pub fn set_enable_cookies(&mut self, enable: bool) {
        self.enable_cookies = enable;
    }

    pub fn cookie_jar(&self) -> &CookieJar {
        &self.cookie_jar
    }

    pub fn cookie_jar_mut(&mut self) -> &mut CookieJar {
        &mut self.cookie_jar
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        self.cookie_jar.add(cookie);
    }

    pub fn clear_cookies(&mut self) {
        self.cookie_jar.clear();
    }

    pub fn with_follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn with_max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn with_dns_resolver(mut self, resolver: DnsResolver) -> Self {
        self.dns_resolver = resolver;
        self
    }

    pub fn with_dns_servers(self, servers: Vec<SocketAddr>) -> Self {
        self.dns_resolver.set_servers(servers);
        self
    }

    pub fn set_accept(&mut self, media_types: Vec<String>) {
        self.default_headers.insert("Accept".to_string(), media_types.join(", "));
    }

    pub fn set_accept_language(&mut self, languages: Vec<String>) {
        self.default_headers.insert("Accept-Language".to_string(), languages.join(", "));
    }

    pub fn set_accept_encoding(&mut self, encodings: Vec<String>) {
        self.default_headers.insert("Accept-Encoding".to_string(), encodings.join(", "));
    }

    pub fn set_accept_charset(&mut self, charsets: Vec<String>) {
        self.default_headers.insert("Accept-Charset".to_string(), charsets.join(", "));
    }

    pub fn set_credentials(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.authenticator.set_credentials(Credentials::new(username, password));
    }

    pub fn set_auto_auth(&mut self, enable: bool) {
        self.auto_auth = enable;
    }

    pub fn auth_execute(&mut self, mut request: HttpRequest) -> io::Result<HttpResponse> {
        let url = self.build_full_url(&request)?;
        let response = self.send_request(&request, &url)?;
        if response.status_code() == 401 && self.auto_auth {
            if let Some(www_auth) = response.header("WWW-Authenticate") {
                if let Ok(challenge) = AuthChallenge::parse(www_auth) {
                    self.cache_challenge(&url, &challenge);

                    let (_, _, _, path) = parse_url(&url)?;
                    let method_str = request.method().as_str();
                    let body = if !request.body_bytes().is_empty() {
                        Some(request.body_bytes())
                    } else {
                        None
                    };

                    if let Ok(auth_header) = self.authenticator.authorize_with_body(
                        &challenge,
                        method_str,
                        &path,
                        body,
                    ) {
                        request.set_header("Authorization", auth_header);
                        return self.send_request(&request, &url);
                    }
                }
            }
        }

        Ok(response)
    }

    pub fn preauth_request(&mut self, mut request: HttpRequest, scheme: &str) -> io::Result<HttpRequest> {
        let url = self.build_full_url(&request)?;
        let (_, _, _, path) = parse_url(&url)?;
        let method_str = request.method().as_str();
        if scheme.to_lowercase() == "basic" {
            if let Ok(auth_header) = self.authenticator.authorize(
                &AuthChallenge::Basic {
                    realm: "".to_string(),
                },
                method_str,
                &path,
            ) {
                request.set_header("Authorization", auth_header);
            }
        } else if scheme.to_lowercase() == "digest" {
            if let Some(cached_challenge) = self.get_cached_challenge(&url) {
                let body = if !request.body_bytes().is_empty() {
                    Some(request.body_bytes())
                } else {
                    None
                };

                if let Ok(auth_header) = self.authenticator.authorize_with_body(
                    &cached_challenge,
                    method_str,
                    &path,
                    body,
                ) {
                    request.set_header("Authorization", auth_header);
                } else {
                    eprintln!("Failed to generate auth header from cached challenge");
                }
            } else {
                eprintln!("Warning: No cached Digest challenge available for {}", url);
            }
        }

        Ok(request)
    }

    fn build_full_url(&self, request: &HttpRequest) -> io::Result<String> {
        let path = request.path();
        if path.starts_with("http://") || path.starts_with("https://") {
            return Ok(path.to_string());
        }

        if let Some(host) = request.headers().get("host") {
            let scheme = if self.preferred_version == HttpVersion::Http2 || self.preferred_version == HttpVersion::Http3 {
                "https"
            } else {
                "http"
            };

            Ok(format!("{}://{}{}", scheme, host, path))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot build full URL: missing Host header",
            ))
        }
    }

    fn cache_challenge(&mut self, url: &str, challenge: &AuthChallenge) {
        let cache_key = self.extract_realm_key(url, challenge);
        self.challenge_cache.insert(
            cache_key,
            CachedChallenge {
                challenge: challenge.clone(),
                cached_at: Instant::now(),
                url_pattern: self.extract_url_pattern(url),
            },
        );
    }

    fn get_cached_challenge(&mut self, url: &str) -> Option<AuthChallenge> {
        self.cleanup_expired_challenges();
        let cache_key = self.extract_cache_key_from_url(url);
        if let Some(cached) = self.challenge_cache.get(&cache_key) {
            if cached.cached_at.elapsed() < self.challenge_cache_ttl {
                return Some(cached.challenge.clone());
            }
        }

        for (_, cached) in self.challenge_cache.iter() {
            if self.url_matches_pattern(url, &cached.url_pattern) {
                if cached.cached_at.elapsed() < self.challenge_cache_ttl {
                    return Some(cached.challenge.clone());
                }
            }
        }

        None
    }

    fn extract_realm_key(&self, url: &str, challenge: &AuthChallenge) -> String {
        let (scheme, host, port, _) = parse_url(url).unwrap_or_default();
        let realm = match challenge {
            AuthChallenge::Basic { realm } => realm.as_str(),
            AuthChallenge::Digest(digest) => digest.realm.as_str(),
        };

        format!("{}:{}:{}:{}", scheme, host, port, realm)
    }

    fn extract_cache_key_from_url(&self, url: &str) -> String {
        let (scheme, host, port, _) = parse_url(url).unwrap_or_default();
        format!("{}:{}:{}", scheme, host, port)
    }

    fn extract_url_pattern(&self, url: &str) -> String {
        let (scheme, host, port, _) = parse_url(url).unwrap_or_default();
        format!("{}://{}:{}", scheme, host, port)
    }

    fn url_matches_pattern(&self, url: &str, pattern: &str) -> bool {
        url.starts_with(pattern)
    }

    fn cleanup_expired_challenges(&mut self) {
        let ttl = self.challenge_cache_ttl;
        self.challenge_cache.retain(|_, cached| cached.cached_at.elapsed() < ttl);
    }

    pub fn clear_challenge_cache(&mut self) {
        self.challenge_cache.clear();
    }

    pub fn set_challenge_cache_ttl(&mut self, ttl: Duration) {
        self.challenge_cache_ttl = ttl;
    }

    pub fn to_secure_profile_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpClientProfileMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_http_client_profile(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate http-client profile nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_http_client_profile_blob_tag(
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
            magic = HTTP_CLIENT_PROFILE_BLOB_MAGIC,
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
            SecureHttpClientProfileMeta {
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

    pub fn to_secure_profile_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpClientProfileMeta, Vec<u8>)> {
        let selected = select_secure_http_client_profile_algorithm(accept_encoding);
        self.to_secure_profile_blob(selected)
    }

    pub fn from_secure_profile_blob(data: &[u8]) -> io::Result<(SecureHttpClientProfileMeta, HttpClient)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_http_client_profile_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "profile digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_http_client_profile_blob_tag(
            &nonce,
            meta.algorithm,
            meta.raw_size,
            body,
        );

        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-client profile HMAC mismatch",
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
        if !constant_time_eq(&actual_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http-client profile digest mismatch",
            ));
        }

        let client = deserialize_http_client_profile(&raw_payload)?;
        Ok((meta, client))
    }

    pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, io::Error> {
        self.send_with_redirects(request, 0)
    }

    fn send_with_redirects(&self, request: &HttpRequest, redirect_count: usize) -> Result<HttpResponse, io::Error> {
        if redirect_count >= self.max_redirects {
            return Err(io::Error::new(io::ErrorKind::Other, "Too many redirects"));
        }

        let url = request.path();
        let (host, port) = self.parse_host_port(url)?;
        let ip_addresses = self.resolve_host(&host)?;
        let mut last_error = None;
        for ip in ip_addresses {
            let addr = SocketAddr::new(ip, port);
            match self.send_to_address(request, addr) {
                Ok(response) => {
                    if self.follow_redirects && response.is_redirect() {
                        if let Some(location) = response.headers().get("Location") {
                            let redirect_request = self.build_redirect_request(request, location)?;
                            return self.send_with_redirects(&redirect_request, redirect_count + 1);
                        }
                    }
                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or(io::Error::new(
            io::ErrorKind::Other,
            "Connection failed",
        )))
    }

    fn send_to_address(&self, request: &HttpRequest, addr: SocketAddr) -> Result<HttpResponse, io::Error> {
        let mut stream = TcpStream::connect(addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if let Some(timeout) = self.timeout {
            stream.set_read_timeout(Some(timeout)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            stream.set_write_timeout(Some(timeout)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        let url = request.path();
        let (_scheme, host, _port, path) = self.parse_host_port(url).and_then(|(h, p)| {
                Ok((
                    "http",
                    h.clone(),
                    p,
                    url.trim_start_matches("http://").trim_start_matches("https://").split('/').skip(1).collect::<Vec<_>>().join("/"),
                ))
            }).map(|(s, h, p, path)| {
                (
                    s,
                    h,
                    p,
                    if path.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", path)
                    },
                )
            })?;

        let request_line = format!("{} {} HTTP/1.1\r\n", request.method().as_str(), path);
        stream.write_all(request_line.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let host_header = format!("Host: {}\r\n", host);
        stream.write_all(host_header.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        for (key, values) in request.headers().iter() {
            if key.to_lowercase() != "host" {
                let header = format!("{}: {}\r\n", key, values.join(", "));
                stream.write_all(header.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
        }

        stream.write_all(b"\r\n").map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if !request.body_bytes().is_empty() {
            stream.write_all(request.body_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        stream.flush().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut reader = BufReader::new(&mut stream);
        self.read_response(&mut reader)
    }

    pub fn send_pipelined(&mut self, requests: Vec<HttpRequest>) -> Result<Vec<HttpResponse>, io::Error> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        if !self.enable_pipelining {
            return requests.into_iter().map(|req| self.send(&req)).collect::<Result<Vec<_>, _>>();
        }

        let first_url = requests[0].path();
        let (host, port) = self.parse_host_port(first_url)?;
        let connection_key = format!("{}:{}", host, port);
        let mut conn = self.get_or_create_http1_connection(&host, port)?;
        if !conn.can_pipeline() {
            return requests.into_iter().map(|req| self.send(&req)).collect::<Result<Vec<_>, _>>();
        }

        for request in requests {
            let request_id = self.next_request_id;
            self.next_request_id += 1;
            conn.enqueue_request(request, request_id)?;
        }

        let responses = conn.flush_pipeline(self.timeout.unwrap_or(Duration::from_secs(30)))?;
        self.http1_connections.insert(connection_key, conn);

        Ok(responses)
    }

    pub fn pipeline_get(&mut self, urls: Vec<&str>) -> Result<Vec<HttpResponse>, io::Error> {
        let requests: Vec<HttpRequest> = urls.into_iter().map(|url| HttpRequest::new(HttpMethod::GET, url)).collect();
        self.send_pipelined(requests)
    }

    fn get_or_create_http1_connection(&mut self, host: &str, port: u16) -> Result<Http1ConnectionEntry, io::Error> {
        let connection_key = format!("{}:{}", host, port);
        if let Some(mut conn) = self.http1_connections.remove(&connection_key) {
            if !conn.should_close() && conn.is_healthy() {
                return Ok(conn);
            }
        }

        let stream = self.connect_to_host(host, port)?;
        stream.set_nodelay(true)?;

        Ok(Http1ConnectionEntry::new(stream, host.to_string(), port))
    }

    pub fn set_pipelining(&mut self, enable: bool) {
        self.enable_pipelining = enable;
    }

    pub fn set_max_pipeline_depth(&mut self, depth: usize) {
        for conn in self.http1_connections.values_mut() {
            conn.max_pipeline_depth = depth;
        }
    }

    fn read_response<R: BufRead>(&self, reader: &mut R) -> Result<HttpResponse, io::Error> {
        let mut status_line = String::new();
        reader.read_line(&mut status_line)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let parts: Vec<&str> = status_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid status line",
            ));
        }

        let version = match parts[0] {
            "HTTP/1.0" => HttpVersion::Http10,
            "HTTP/1.1" => HttpVersion::Http11,
            "HTTP/2.0" => HttpVersion::Http2,
            _ => HttpVersion::Http2,
        };

        let status_code: u16 = parts[1].parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid status code"))?;
        let reason_phrase = parts[2..].join(" ");
        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() {
                break;
            }

            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        let body = if let Some(content_length) = headers.get("Content-Length") {
            let length: usize = content_length.parse().unwrap_or(0);
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body)?;
            body
        } else if headers.get("Transfer-Encoding").map(|s| s.as_str()) == Some("chunked") {
            read_chunked_body(reader)?
        } else {
            let mut body = Vec::new();
            reader.read_to_end(&mut body)?;
            body
        };

        Ok(HttpResponse::new(
            status_code,
            reason_phrase,
            version,
            headers,
            body,
        ))
    }

    fn send_request(&mut self, request: &HttpRequest, url: &str) -> io::Result<HttpResponse> {
        let (scheme, host, port, path) = parse_url(url)?;
        let use_http2 = scheme == "https" && (self.preferred_version == HttpVersion::Http2 || self.enable_version_negotiation);
        if use_http2 {
            match self.send_http2_request(request, &host, port, &path) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    eprintln!("HTTP/2 failed, falling back to HTTP/1.1: {}", e);
                }
            }
        }

        self.send_http1_request(request, &host, port, &path)
    }

    fn send_http1_request(&mut self, request: &HttpRequest, host: &str, port: u16, path: &str) -> io::Result<HttpResponse> {
        let connection_key = format!("{}:{}", host, port);
        let mut conn = if let Some(existing) = self.http1_connections.remove(&connection_key) {
            if existing.is_stale(self.idle_timeout) || existing.should_close() {
                self.create_http1_connection(host, port)?
            } else {
                existing
            }
        } else {
            self.create_http1_connection(host, port)?
        };

        let mut modified_request = if request.path() != path {
            let new_url = request.path().to_string();
            let mut new_request = HttpRequest::new(request.method().clone(), &new_url);
            for (key, values) in request.headers().iter() {
                for value in values {
                    new_request.headers_mut().append(key.clone(), value.clone());
                }
            }

            new_request.set_body(request.body_bytes().to_vec())
        } else {
            request.clone()
        };

        modified_request.set_header("Host".to_string(), host.to_string());

        let wants_keep_alive = request
            .headers()
            .get("Connection")
            .map(|value| value.to_lowercase() != "close")
            .unwrap_or(true);

        if self.enable_pipelining || wants_keep_alive {
            modified_request.set_header("Connection".to_string(), "keep-alive".to_string());
        }

        let request_bytes = modified_request.build(host);
        conn.stream.write_all(&request_bytes)?;
        conn.stream.flush()?;
        let response = self.read_http1_response(&mut conn.stream)?;
        conn.mark_used();
        if response.wants_keep_alive() && !conn.should_close() {
            self.http1_connections.insert(connection_key, conn);
        }

        Ok(response)
    }

    fn send_http2_request(&mut self, request: &HttpRequest, host: &str, port: u16, path: &str) -> io::Result<HttpResponse> {
        let connection_key = format!("{}:{}", host, port);
        let conn = if let Some(existing) = self.http2_connections.get_mut(&connection_key) {
            existing
        } else {
            let tcp_stream = self.connection_pool.get_or_connect(host, port, PooledProtocol::Http2)?;
            let http2_conn = Http2Connection::new(tcp_stream)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let mut entry = Http2ConnectionEntry::new(http2_conn, host.to_string(), port);
            entry.connection.handshake()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            self.http2_connections.insert(connection_key.clone(), entry);
            self.http2_connections.get_mut(&connection_key).unwrap()
        };

        let stream_id = conn.create_tracked_stream(path.to_string())?;
        let mut headers = vec![
            (":method".to_string(), request.method().as_str().to_string()),
            (":path".to_string(), path.to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), host.to_string()),
        ];

        for (key, values) in request.headers().iter() {
            for value in values {
                headers.push((key.to_lowercase(), value.clone()));
            }
        }

        conn.connection.send_request(stream_id, headers, Some(request.body_bytes().to_vec()))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let (response_headers, body) = conn.receive_response_with_timeout(
            stream_id,
            self.timeout.unwrap_or(Duration::from_secs(30)),
        )?;

        conn.remove_stream(stream_id);
        let status_code = response_headers.get(":status")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);

        let reason = HttpResponse::default_reason_phrase(status_code);
        let mut headers_map = HashMap::new();
        for (key, value) in response_headers {
            if !key.starts_with(':') {
                headers_map.insert(key, value);
            }
        }

        Ok(HttpResponse::new(
            status_code,
            reason,
            HttpVersion::Http2,
            headers_map,
            body,
        ))
    }

    fn create_http1_connection(&self, host: &str, port: u16) -> io::Result<Http1ConnectionEntry> {
        let tcp_stream = self.connection_pool.get_or_connect(host, port, PooledProtocol::Http1)?;
        tcp_stream.set_read_timeout(self.timeout)?;
        tcp_stream.set_write_timeout(self.timeout)?;

        Ok(Http1ConnectionEntry::new(
            tcp_stream,
            host.to_string(),
            port,
        ))
    }

    fn parse_host_port(&self, url: &str) -> Result<(String, u16), io::Error> {
        let url = url.trim_start_matches("http://").trim_start_matches("https://");
        let host_part = url.split('/').next().unwrap_or(url);
        if let Some(colon_pos) = host_part.rfind(':') {
            let host = host_part[..colon_pos].to_string();
            let port_str = &host_part[colon_pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number"))?;
            Ok((host, port))
        } else {
            let port = if url.starts_with("https://") { 443 } else { 80 };
            Ok((host_part.to_string(), port))
        }
    }

    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, io::Error> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        self.dns_resolver.resolve_host(host).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("DNS resolution failed for {}: {}", host, e),
            )
        })
    }

    fn connect_to_host(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let ip_addresses = self.resolve_host(host)?;
        let mut last_error = None;
        for ip in ip_addresses {
            match TcpStream::connect(SocketAddr::new(ip, port)) {
                Ok(stream) => return Ok(stream),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to connect to {}:{}", host, port))
        }))
    }

    fn build_redirect_request(&self, original: &HttpRequest, location: &str) -> Result<HttpRequest, io::Error> {
        let mut new_request = HttpRequest::new(original.method().clone(), location.to_string());
        if let Some(user_agent) = original.headers().get("User-Agent") {
            new_request.headers_mut().insert("User-Agent".to_string(), user_agent);
        }

        if let Some(accept) = original.headers().get("Accept") {
            new_request.headers_mut().insert("Accept".to_string(), accept);
        }

        Ok(new_request)
    }

    pub fn dns_resolver(&self) -> &DnsResolver {
        &self.dns_resolver
    }

    pub fn clear_dns_cache(&self) {
        self.dns_resolver.clear_cache();
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(HttpMethod::GET, url);
        self.execute(request)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, io::Error> {
        let mut request = HttpRequest::new(HttpMethod::POST, url);
        request = request.set_body(body);
        self.execute(request)
    }

    pub fn head(&self, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(HttpMethod::HEAD, url);
        self.send(&request)
    }

    pub fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, io::Error> {
        let mut request = HttpRequest::new(HttpMethod::PUT, url);
        request = request.set_body(body);
        self.send(&request)
    }

    pub fn delete(&self, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(HttpMethod::DELETE, url);
        self.send(&request)
    }

    pub fn patch(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, io::Error> {
        let mut request = HttpRequest::new(HttpMethod::PATCH, url);
        request = request.set_body(body);
        self.send(&request)
    }

    fn add_cookies_to_request(&mut self, request: &mut HttpRequest) -> Result<(), io::Error> {
        let url = request.path();
        let (scheme, host, _port, path) = parse_url(url)?;

        self.cookie_jar.remove_expired();
        let secure = scheme == "https";
        if let Some(cookie_header) = self.cookie_jar.cookie_header(&host, &path, secure) {
            request.set_header("Cookie".to_string(), cookie_header);
        }

        Ok(())
    }

    fn store_cookies_from_response(&mut self, response: &HttpResponse, url: &str) -> Result<(), io::Error> {
        if !self.enable_cookies {
            return Ok(());
        }

        let (_scheme, host, _port, path) = parse_url(url)?;
        for (key, value) in response.headers() {
            if key.to_lowercase() == "set-cookie" {
                match parse_set_cookie(value) {
                    Ok(mut cookie) => {
                        if cookie.domain().is_none() {
                            cookie.set_domain(host.clone());
                        }

                        if cookie.path().is_none() {
                            cookie.set_path(Some(path.clone()));
                        }

                        self.cookie_jar.add(cookie);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse Set-Cookie header: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn execute(&mut self, mut request: HttpRequest) -> Result<HttpResponse, io::Error> {
        for (key, value) in &self.default_headers {
            if request.headers().get(key).is_none() {
                request.set_header(key.clone(), value.clone());
            }
        }

        if request.headers().get("User-Agent").is_none() {
            request.set_header("User-Agent".to_string(), self.user_agent.clone());
        }

        if self.enable_cookies {
            self.add_cookies_to_request(&mut request)?;
        }

        self.execute_with_redirects(request, 0)
    }

    fn execute_with_redirects(&mut self, request: HttpRequest, redirect_count: usize) -> Result<HttpResponse, io::Error> {
        if redirect_count > self.max_redirects {
            return Err(io::Error::new(io::ErrorKind::Other, "Too many redirects"));
        }

        let url = request.path().to_string();
        let response = self.execute_internal(request.clone())?;
        self.store_cookies_from_response(&response, &url)?;
        if self.follow_redirects && response.is_redirect() {
            if let Some(location) = response.headers().get("Location") {
                let new_url = resolve_url(request.path(), location);
                let new_request = HttpRequest::new(request.method().clone(), &new_url);
                return self.execute_with_redirects(new_request, redirect_count + 1);
            }
        }

        Ok(response)
    }

    fn execute_internal(&mut self, request: HttpRequest) -> Result<HttpResponse, io::Error> {
        let url = request.path().to_string();
        let (scheme, _host, _port, _path) = parse_url(&url)?;
        let negotiated_version = self.negotiate_version(&url, &scheme);
        let use_http2 = negotiated_version == HttpVersion::Http2 && scheme == "https";
        let response = if use_http2 {
            self.execute_http2(request)
        } else {
            self.execute_http1(request)
        }?;

        self.store_negotiated_version(&url, negotiated_version);
        if let Some(alt_svc) = response.headers().get("Alt-Svc") {
            self.process_alt_svc_header(&url, alt_svc);
        }

        Ok(response)
    }

    fn execute_http1(&mut self, mut request: HttpRequest) -> Result<HttpResponse, io::Error> {
        let url = request.path();
        let (_scheme, host, port, path) = parse_url(url)?;
        let connection_key = format!("{}:{}", host, port);
        let body_len = request.body_bytes().len();
        let use_expect_continue = body_len > self.expect_100_continue_threshold;
        if use_expect_continue {
            request.set_header("Expect".to_string(), "100-continue".to_string());
        }

        let use_keep_alive = request.headers().get("Connection").map(|s| s.to_lowercase() != "close").unwrap_or(true);
        let mut stream_option: Option<TcpStream> = None;
        let mut _reused_connection = false;
        if use_keep_alive {
            self.cleanup_idle_connections();
            if let Some(entry) = self.http1_connections.get_mut(&connection_key) {
                if !entry.is_stale(self.connection_timeout) && !entry.should_close() && entry.is_healthy() {
                    let mut entry = self.http1_connections.remove(&connection_key).unwrap();
                    entry.mark_used();
                    stream_option = Some(entry.stream);
                    _reused_connection = true;
                }
            }
        }

        let mut stream = if let Some(s) = stream_option {
            s
        } else {
            self.connect_to_host(&host, port)?
        };

        if let Some(timeout) = self.timeout {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
        }

        stream.set_nodelay(true)?;
        let request_line = format!("{} {} HTTP/1.1\r\n", request.method().as_str(), path);
        stream.write_all(request_line.as_bytes())?;
        let host_header = format!("Host: {}:{}\r\n", host, port);
        stream.write_all(host_header.as_bytes())?;
        for (key, values) in request.headers().iter() {
            if key.to_lowercase() != "host" {
                let header = format!("{}: {}\r\n", key, values.join(", "));
                stream.write_all(header.as_bytes())?;
            }
        }

        if request.headers().get("Connection").is_none() {
            if use_keep_alive {
                stream.write_all(b"Connection: keep-alive\r\n")?;
            } else {
                stream.write_all(b"Connection: close\r\n")?;
            }
        }

        if use_expect_continue {
            stream.write_all(b"\r\n")?;
            stream.flush()?;
            let mut reader = BufReader::new(&stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line)?;
            let parts: Vec<&str> = status_line.trim().split_whitespace().collect();
            if parts.len() >= 2 {
                let status: u16 = parts[1].parse().unwrap_or(0);
                if status == 100 {
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    stream.write_all(request.body_bytes())?;
                    stream.flush()?;
                } else if status >= 400 {
                    drop(reader);
                    return self.read_http1_response(&mut stream);
                }
            }
        } else {
            stream.write_all(b"\r\n")?;
            let body = request.body_bytes();
            if !body.is_empty() {
                stream.write_all(body)?;
            }

            stream.flush()?;
        }

        self.read_http1_response(&mut stream)
    }

    fn read_http1_response(&self, stream: &mut TcpStream) -> io::Result<HttpResponse> {
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;
        let parts: Vec<&str> = status_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid status line",
            ));
        }

        let version = HttpVersion::from_str(parts[0]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP version"))?;
        let status_code = parts[1].parse::<u16>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid status code"))?;
        let reason_phrase = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();
        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() {
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        let body = if let Some(content_length_str) = headers.get("content-length") {
            let content_length = content_length_str.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid content-length")
            })?;

            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            body
        } else if headers.get("transfer-encoding").map(|v| v.as_str()) == Some("chunked") {
            read_chunked_body(&mut reader)?
        } else {
            Vec::new()
        };

        Ok(HttpResponse::new(
            status_code,
            reason_phrase,
            version,
            headers,
            body,
        ))
    }

    fn execute_http2(&mut self, request: HttpRequest) -> Result<HttpResponse, io::Error> {
        let url = request.path();
        let (scheme, host, port, path) = parse_url(url)?;
        let connection_key = format!("{}:{}", host, port);
        let entry = self.get_or_create_http2_connection(&connection_key, &host, port)?;
        let stream_id = entry.create_tracked_stream(url.to_string())?;
        let body = request.body_bytes();
        let mut headers = vec![
            (":method".to_string(), request.method().as_str().to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), scheme),
            (":authority".to_string(), format!("{}:{}", host, port)),
        ];

        for (key, values) in request.headers().iter() {
            for value in values {
                headers.push((key.to_lowercase(), value.clone()));
            }
        }

        entry.connection.send_request(stream_id, headers, Some(body.to_vec())).ok();
        if !body.is_empty() {
            entry.connection.send_data(stream_id, body, true).ok();
        }

        let response = Self::extract_http2_response(entry, stream_id)?;

        Ok(response)
    }

    fn get_or_create_http2_connection(&mut self, connection_key: &str, host: &str, port: u16) -> Result<&mut Http2ConnectionEntry, io::Error> {
        if !self.http2_connections.contains_key(connection_key) {
            let stream = self.connect_to_host(host, port)?;
            let connection = Http2Connection::new(stream).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create HTTP/2 connection: {:?}", e),
                )
            })?;

            let entry = Http2ConnectionEntry::new(connection, host.to_string(), port);
            self.http2_connections.insert(connection_key.to_string(), entry);
        }

        Ok(self.http2_connections.get_mut(connection_key).unwrap())
    }

    fn extract_http2_response(entry: &mut Http2ConnectionEntry, stream_id: u32) -> Result<HttpResponse, io::Error> {
        let (headers, body) = entry.receive_response(stream_id)?;

        let mut status_code = 200;
        let mut response_headers = HashMap::new();
        for (key, value) in headers {
            if key == ":status" {
                status_code = value.parse().unwrap_or(200);
            } else if !key.starts_with(':') {
                response_headers.insert(key, value);
            }
        }

        Ok(HttpResponse::new(
            status_code,
            String::new(),
            HttpVersion::Http2,
            response_headers,
            body,
        ))
    }

    pub fn with_http3(mut self, enable: bool) -> Self {
        self.enable_http3 = enable;
        if enable {
            self.http3_client = Some(Http3Client::new());
        }

        self
    }

    pub fn set_http3_config(&mut self, config: Http3Config) {
        self.http3_client = Some(Http3Client::with_config(config));
        self.enable_http3 = true;
    }

    fn send_request_internal(&mut self, request: &HttpRequest, url: &str) -> io::Result<HttpResponse> {
        if self.enable_http3 {
            if let Some(http3_info) = self.check_alt_svc(url) {
                return self.send_http3_request(request, http3_info);
            }
        }

        self.send_request(request, url)
    }

    fn check_alt_svc(&self, url: &str) -> Option<(String, u16)> {
        self.alt_svc_cache.get(url).and_then(|entries| {
            entries.iter().find(|(version, _, _)| *version == HttpVersion::Http3).map(|(_, host, port)| (host.clone(), *port))
        })
    }

    fn send_http3_request(&mut self, request: &HttpRequest, (_host, _port): (String, u16)) -> io::Result<HttpResponse> {
        if self.http3_client.is_none() {
            self.http3_client = Some(Http3Client::new());
        }

        let client = self.http3_client.as_mut().unwrap();
        client.request(request.clone()).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("HTTP/3 error: {}", e))
        })
    }

    pub fn cleanup_http3(&mut self) {
        if let Some(ref mut client) = self.http3_client {
            client.cleanup();
        }
    }

    fn read_trailing_headers(&self, reader: &mut BufReader<TcpStream>, has_trailer_header: bool, expected_trailers: &[String]) -> Result<HashMap<String, String>, io::Error> {
        let mut trailers = HashMap::new();
        let mut found_trailers: Vec<String> = Vec::new();
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if line.trim().is_empty() || bytes_read == 0 {
                break;
            }

            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                let key_lower = key.to_lowercase();
                if self.is_forbidden_trailer(&key_lower) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Forbidden trailer field: {}", key),
                    ));
                }

                if has_trailer_header && !expected_trailers.contains(&key_lower) {
                    eprintln!(
                        "Warning: Unexpected trailer header '{}' not listed in Trailer header",
                        key
                    );
                }

                found_trailers.push(key_lower.clone());
                trailers.insert(key, value);
            } else if !line.trim().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Malformed trailer line: {}", line.trim()),
                ));
            }
        }

        if has_trailer_header {
            for expected in expected_trailers {
                if !found_trailers.contains(expected) {
                    eprintln!("Warning: Expected trailer '{}' was not received", expected);
                }
            }
        }

        Ok(trailers)
    }

    fn is_forbidden_trailer(&self, field_name: &str) -> bool {
        matches!(
            field_name,
            "transfer-encoding"
                | "content-length"
                | "host"
                | "cache-control"
                | "expect"
                | "max-forwards"
                | "pragma"
                | "range"
                | "te"
                | "authorization"
                | "set-cookie"
                | "cookie"
                | "content-encoding"
                | "content-type"
                | "content-range"
                | "trailer"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "upgrade"
                | "via"
                | "warning"
                | "if-match"
                | "if-none-match"
                | "if-modified-since"
                | "if-unmodified-since"
                | "if-range"
        )
    }

    fn negotiate_version(&self, url: &str, scheme: &str) -> HttpVersion {
        if !self.enable_version_negotiation {
            return self.preferred_version;
        }

        let (_, host, port, _) = match parse_url(url) {
            Ok(parts) => parts,
            Err(_) => return self.preferred_version,
        };

        let connection_key = format!("{}:{}", host, port);
        if let Some(&cached_version) = self.version_cache.get(&connection_key) {
            return cached_version;
        }

        if let Some(alt_svcs) = self.alt_svc_cache.get(&connection_key) {
            for (version, _, _) in alt_svcs {
                if *version == HttpVersion::Http2 && scheme == "https" {
                    return HttpVersion::Http2;
                }
            }
        }

        if scheme == "https" && self.preferred_version == HttpVersion::Http2 {
            return HttpVersion::Http2;
        }

        self.preferred_version
    }

    fn store_negotiated_version(&mut self, url: &str, version: HttpVersion) {
        if let Ok((_, host, port, _)) = parse_url(url) {
            let connection_key = format!("{}:{}", host, port);
            self.version_cache.insert(connection_key, version);
        }
    }

    fn process_alt_svc_header(&mut self, url: &str, alt_svc: &str) {
        if let Ok((_, host, port, _)) = parse_url(url) {
            let connection_key = format!("{}:{}", host, port);
            let mut alternatives = Vec::new();
            for entry in alt_svc.split(',') {
                let entry = entry.trim();
                if entry.contains("h2=") {
                    if let Some(start) = entry.find('"') {
                        if let Some(end) = entry[start + 1..].find('"') {
                            let alt_host_port = &entry[start + 1..start + 1 + end];
                            if let Some(colon_pos) = alt_host_port.rfind(':') {
                                let alt_host = alt_host_port[..colon_pos].to_string();
                                if let Ok(alt_port) = alt_host_port[colon_pos + 1..].parse::<u16>() {
                                    alternatives.push((HttpVersion::Http2, alt_host, alt_port));
                                }
                            }
                        }
                    }
                }
            }

            if !alternatives.is_empty() {
                self.alt_svc_cache.insert(connection_key, alternatives);
            }
        }
    }

    fn cleanup_idle_connections(&mut self) {
        self.http1_connections.retain(|_, entry| {
            !entry.is_idle_timeout() && !entry.should_close() && entry.is_healthy()
        });
    }

    pub fn cleanup_connections(&mut self) {
        let now = Instant::now();
        self.http1_connections.retain(|_, entry| {
            !entry.is_stale(self.connection_timeout) && !entry.should_close()
        });

        self.http2_connections.retain(|_, entry| {
            let is_stale = now.duration_since(entry.last_used) > self.connection_timeout;
            let has_streams = !entry.active_streams.is_empty();
            !(is_stale && !has_streams)
        });
    }

    pub fn connection_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("http1_connections".to_string(), self.http1_connections.len());
        stats.insert("http2_connections".to_string(), self.http2_connections.len());
        let total_streams: usize = self.http2_connections.values().map(|e| e.active_stream_count()).sum();
        stats.insert("active_streams".to_string(), total_streams);
        let max_streams: usize = self.http2_connections.values().map(|e| e.max_concurrent_streams).max().unwrap_or(0);
        stats.insert("max_concurrent_streams".to_string(), max_streams);
        stats.insert("total_cookies".to_string(), self.cookie_jar.len());
        stats.insert("cached_versions".to_string(), self.version_cache.len());
        stats.insert("alt_svc_entries".to_string(), self.alt_svc_cache.len());

        stats
    }

    pub fn connection_info(&self) -> Vec<ConnectionInfo> {
        let mut infos = Vec::new();
        for (key, entry) in &self.http1_connections {
            infos.push(ConnectionInfo {
                host: entry.host.clone(),
                port: entry.port,
                connection_key: key.clone(),
                active_streams: 1,
                max_concurrent_streams: 1,
                last_used: entry.last_used,
                age: entry.last_used.elapsed(),
                is_http2: false,
                requests_made: entry.requests_made,
            });
        }

        for (key, entry) in &self.http2_connections {
            infos.push(ConnectionInfo {
                host: entry.host.clone(),
                port: entry.port,
                connection_key: key.clone(),
                active_streams: entry.active_stream_count(),
                max_concurrent_streams: entry.max_concurrent_streams,
                last_used: entry.last_used,
                age: entry.last_used.elapsed(),
                is_http2: true,
                requests_made: 0,
            });
        }

        infos
    }

    pub fn request(&mut self, method: HttpMethod, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(method, url);
        self.execute(request)
    }

    pub fn simple_request(&mut self, method: &str, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse, io::Error> {
        let http_method = HttpMethod::from_str(method).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid HTTP method: {}", method),
            )
        })?;

        let mut request = HttpRequest::new(http_method, url);
        if let Some(body_data) = body {
            request = request.set_body(body_data);
        }

        self.execute(request)
    }

    pub fn cleanup_old_connections(&mut self) {
        self.cleanup_idle_connections();
    }

    pub fn active_connections(&self) -> usize {
        self.http1_connections.len() + self.http2_connections.len()
    }

    pub fn has_connection(&self, host: &str, port: u16) -> bool {
        let key = format!("{}:{}", host, port);
        self.http1_connections.contains_key(&key) || self.http2_connections.contains_key(&key)
    }

    pub fn close_connection(&mut self, host: &str, port: u16) -> Result<(), io::Error> {
        let key = format!("{}:{}", host, port);
        if let Some(entry) = self.http1_connections.remove(&key) {
            let _ = entry.stream.shutdown(std::net::Shutdown::Both);
        }

        if let Some(mut entry) = self.http2_connections.remove(&key) {
            let _ = entry.connection.close();
        }

        Ok(())
    }

    pub fn set_keep_alive(&mut self, _enable: bool) {}

    pub fn is_keep_alive(&self) -> bool {
        true
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Http1ConnectionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http1Connection {{ host: {}:{}, requests: {}, age: {:?}, idle: {:?} }}",
            self.host,
            self.port,
            self.requests_made,
            self.age(),
            self.last_used.elapsed()
        )
    }
}

impl std::fmt::Display for Http2ConnectionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http2Connection {{ host: {}:{}, streams: {}/{}, idle: {:?} }}",
            self.host,
            self.port,
            self.active_stream_count(),
            self.max_concurrent_streams,
            self.last_used.elapsed()
        )
    }
}

pub fn select_secure_http_client_profile_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algo, quality)| {
        if quality > 0.0 && algo.is_implemented() {
            Some(algo)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

fn serialize_http_client_profile(client: &HttpClient) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!("user-agent={}", pem::encode(client.user_agent.as_bytes())));
    lines.push(format!("preferred-version={}", client.preferred_version.as_str()));
    lines.push(format!(
        "timeout-ms={}",
        client.timeout.map(|d| d.as_millis().to_string()).unwrap_or_else(|| "none".to_string())
    ));

    lines.push(format!("follow-redirects={}", client.follow_redirects));
    lines.push(format!("max-redirects={}", client.max_redirects));
    lines.push(format!("max-connections-per-host={}", client.max_connections_per_host));
    lines.push(format!("connection-timeout-ms={}", client.connection_timeout.as_millis()));
    lines.push(format!("stream-timeout-ms={}", client.stream_timeout.as_millis()));
    lines.push(format!("idle-timeout-ms={}", client.idle_timeout.as_millis()));
    lines.push(format!("enable-pipelining={}", client.enable_pipelining));
    lines.push(format!("expect-100-continue-threshold={}", client.expect_100_continue_threshold));
    lines.push(format!("enable-cookies={}", client.enable_cookies));
    lines.push(format!("enable-version-negotiation={}", client.enable_version_negotiation));
    lines.push(format!("auto-auth={}", client.auto_auth));
    lines.push(format!("challenge-cache-ttl-ms={}", client.challenge_cache_ttl.as_millis()));
    lines.push(format!("enable-http3={}", client.enable_http3));
    let mut headers: Vec<(&String, &String)> = client.default_headers.iter().collect();
    headers.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in headers {
        lines.push(format!(
            "header={}|{}",
            pem::encode(k.as_bytes()),
            pem::encode(v.as_bytes())
        ));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_http_client_profile(raw_payload: &[u8]) -> io::Result<HttpClient> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "http-client profile payload is not valid UTF-8",
        )
    })?;

    let mut client = HttpClient::new();
    let mut default_headers = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (k, v) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile payload line '{}'", trimmed),
            )
        })?;

        match k {
            "user-agent" => {
                let bytes = pem::decode(v).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid user-agent encoding: {}", e),
                    )
                })?;

                client.user_agent = String::from_utf8(bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "user-agent is not valid UTF-8")
                })?;
            }
            "preferred-version" => {
                client.preferred_version = HttpVersion::from_str(v).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid preferred-version '{}'", v),
                    )
                })?;
            }
            "timeout-ms" => {
                client.timeout = if v == "none" {
                    None
                } else {
                    Some(Duration::from_millis(v.parse::<u64>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid timeout-ms")
                    })?))
                };
            }
            "follow-redirects" => {
                client.follow_redirects = parse_bool(v)?;
            }
            "max-redirects" => {
                client.max_redirects = v.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid max-redirects")
                })?;
            }
            "max-connections-per-host" => {
                client.max_connections_per_host = v.parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid max-connections-per-host",
                    )
                })?;
            }
            "connection-timeout-ms" => {
                client.connection_timeout = Duration::from_millis(v.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid connection-timeout-ms")
                })?);
            }
            "stream-timeout-ms" => {
                client.stream_timeout = Duration::from_millis(v.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid stream-timeout-ms")
                })?);
            }
            "idle-timeout-ms" => {
                client.idle_timeout = Duration::from_millis(v.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid idle-timeout-ms")
                })?);
            }
            "enable-pipelining" => {
                client.enable_pipelining = parse_bool(v)?;
            }
            "expect-100-continue-threshold" => {
                client.expect_100_continue_threshold = v.parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid expect-100-continue-threshold",
                    )
                })?;
            }
            "enable-cookies" => {
                client.enable_cookies = parse_bool(v)?;
            }
            "enable-version-negotiation" => {
                client.enable_version_negotiation = parse_bool(v)?;
            }
            "auto-auth" => {
                client.auto_auth = parse_bool(v)?;
            }
            "challenge-cache-ttl-ms" => {
                client.challenge_cache_ttl = Duration::from_millis(v.parse::<u64>().map_err(
                    |_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid challenge-cache-ttl-ms",
                        )
                    },
                )?);
            }
            "enable-http3" => {
                client.enable_http3 = parse_bool(v)?;
                if client.enable_http3 && client.http3_client.is_none() {
                    client.http3_client = Some(Http3Client::new());
                }
            }
            "header" => {
                let (k_b64, v_b64) = v.split_once('|').ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid header profile line")
                })?;

                let key = String::from_utf8(pem::decode(k_b64).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid header key encoding: {}", e),
                    )
                })?).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "header key is not valid UTF-8")
                })?;

                let value = String::from_utf8(pem::decode(v_b64).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid header value encoding: {}", e),
                    )
                })?).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "header value is not valid UTF-8")
                })?;

                default_headers.insert(key, value);
            }
            _ => {}
        }
    }

    client.default_headers = default_headers;
    Ok(client)
}

fn compute_http_client_profile_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP_CLIENT_PROFILE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP_CLIENT_PROFILE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "profile header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "profile header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "profile blob missing header/body separator",
    ))
}

fn parse_secure_http_client_profile_meta(header: &str, body_len: usize) -> io::Result<SecureHttpClientProfileMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_CLIENT_PROFILE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid http-client profile blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile header line '{}'", line),
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
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();
                
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in profile blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in profile blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in profile blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in profile blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in profile blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in profile blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in profile blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in profile blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in profile blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "profile encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttpClientProfileMeta {
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

fn parse_url(url: &str) -> Result<(String, String, u16, String), io::Error> {
    let url_lower = url.to_lowercase();
    let (scheme, rest) = if url_lower.starts_with("http://") {
        ("http", &url[7..])
    } else if url_lower.starts_with("https://") {
        ("https", &url[8..])
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "URL must start with http:// or https://",
        ));
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "/")
    };

    let (host, port) = if let Some(pos) = host_port.find(':') {
        let host = host_port[..pos].to_string();
        let port = host_port[pos + 1..].parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number"))?;
        (host, port)
    } else {
        (host_port.to_string(), default_port)
    };

    Ok((scheme.to_string(), host, port, path.to_string()))
}

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return relative.to_string();
    }

    if let Ok((scheme, host, port, path)) = parse_url(base) {
        let default_port = if scheme == "https" { 443 } else { 80 };
        let authority = if port == default_port {
            host
        } else {
            format!("{}:{}", host, port)
        };

        if relative.starts_with('/') {
            format!("{}://{}{}", scheme, authority, relative)
        } else {
            let dir = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
            format!("{}://{}{}/{}", scheme, authority, dir, relative)
        }
    } else {
        relative.to_string()
    }
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, io::Error> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;

        let size_str = size_line.trim().split(';').next().unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid chunk size"))?;
        if chunk_size == 0 {
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (scheme, host, port, path) = parse_url("http://example.com/path").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");

        let (scheme, host, port, path) = parse_url("https://example.com:8443/path").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_resolve_url() {
        let base = "http://example.com/a/b/c";
        let relative = "/new/path";
        assert_eq!(resolve_url(base, relative), "http://example.com/new/path");

        let relative = "relative";
        assert_eq!(resolve_url(base, relative), "http://example.com/a/b/relative");
    }
}