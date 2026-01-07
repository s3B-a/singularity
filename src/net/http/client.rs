use super::http2::Http2Connection;
use super::method::HttpMethod;
use super::version::HttpVersion;
use super::request::HttpRequest;
use super::response::HttpResponse;
use crate::net::tcp::TcpStream;
use crate::net::cookie::{CookieJar, Cookie, parse_set_cookie};
use crate::net::dns::DnsResolver;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};

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
        self.supports_pipelining && self.pending_requests < 5
    }

    fn is_healthy(&mut self) -> bool {
        let mut buf = [0u8; 1];
        match self.stream.peek(&mut buf) {
            Ok(0) => false, // Connection closed
            Ok(_) => true,  // Data available or connection alive
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(_) => false, // Connection error
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

        let stream_id = self.connection.create_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create stream: {:?}", e)))?;

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
        self.connection.receive_frames()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to process frames: {:?}", e)))?;
        
        self.cleanup_finished_streams()?;
        
        Ok(())
    }

    pub fn receive_response(&mut self, stream_id: u32) -> Result<(HashMap<String, String>, Vec<u8>), io::Error> {
        let stream = self.connection.get_stream_mut(stream_id)
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Stream {} not found", stream_id)
            ))?;
        
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
            
            let stream = self.connection.get_stream(stream_id)
                .ok_or_else(|| io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Stream {} not found", stream_id)
                ))?;
            
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

    pub fn build(self) -> HttpClient {
        self.client
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

        Err(last_error.unwrap_or(io::Error::new(io::ErrorKind::Other, "Connection failed")))
    }

    fn send_to_address(&self, request: &HttpRequest, addr: SocketAddr) -> Result<HttpResponse, io::Error> {
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if let Some(timeout) = self.timeout {
            stream.set_read_timeout(Some(timeout))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            stream.set_write_timeout(Some(timeout))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        let url = request.path();
        let (_scheme, host, _port, path) = self.parse_host_port(url)
            .and_then(|(h, p)| Ok(("http", h.clone(), p, url.trim_start_matches("http://").trim_start_matches("https://").split('/').skip(1).collect::<Vec<_>>().join("/"))))
            .map(|(s, h, p, path)| (s, h, p, if path.is_empty() { "/".to_string() } else { format!("/{}", path) }))?;
        
        let request_line = format!("{} {} HTTP/1.1\r\n", request.method().as_str(), path);
        stream.write_all(request_line.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let host_header = format!("Host: {}\r\n", host);
        stream.write_all(host_header.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        for (key, values) in request.headers().iter() {
            if key.to_lowercase() != "host" {
                let header = format!("{}: {}\r\n", key, values.join(", "));
                stream.write_all(header.as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
        }
        
        stream.write_all(b"\r\n")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        if !request.get_body().is_empty() {
            stream.write_all(request.get_body())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        
        stream.flush()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut reader = BufReader::new(&mut stream);
        self.read_response(&mut reader)
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

        let status_code: u16 = parts[1].parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid status code")
        })?;

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

        self.dns_resolver
            .resolve_host(host)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("DNS resolution failed for {}: {}", host, e)))
    }

    fn build_redirect_request(&self, original: &HttpRequest, location: &str) -> Result<HttpRequest, io::Error> {
        let mut new_request = HttpRequest::new(original.method().clone(), location.to_string());
        if let Some(user_agent) = original.headers().get("User-Agent") {
            new_request.headers_mut().insert("User-Agent".to_string(), user_agent.clone());
        }
        if let Some(accept) = original.headers().get("Accept") {
            new_request.headers_mut().insert("Accept".to_string(), accept.clone());
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
        request.set_body(body);
        self.execute(request)
    }

    pub fn head(&self, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(HttpMethod::HEAD, url);
        self.send(&request)
    }

    pub fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, io::Error> {
        let mut request = HttpRequest::new(HttpMethod::PUT, url);
        request.set_body(body);
        self.send(&request)
    }

    pub fn delete(&self, url: &str) -> Result<HttpResponse, io::Error> {
        let request = HttpRequest::new(HttpMethod::DELETE, url);
        self.send(&request)
    }

    pub fn patch(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, io::Error> {
        let mut request = HttpRequest::new(HttpMethod::PATCH, url);
        request.set_body(body);
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
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Too many redirects",
            ));
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
        let url = request.path();
        let (scheme, _host, _port, _path) = parse_url(url)?;
        let use_http2 = self.preferred_version == HttpVersion::Http2 && scheme == "https";
        if use_http2 {
            self.execute_http2(request)
        } else {
            self.execute_http1(request)
        }
    }

    fn execute_http1(&mut self, mut request: HttpRequest) -> Result<HttpResponse, io::Error> {
        let url = request.path();
        let (_scheme, host, port, path) = parse_url(url)?;
        let connection_key = format!("{}:{}", host, port);

        let body_len = request.get_body().len();
        let use_expect_continue = body_len > self.expect_100_continue_threshold;
        
        if use_expect_continue {
            request.set_header("Expect".to_string(), "100-continue".to_string());
        }

        let use_keep_alive = request.headers()
            .get("Connection")
            .map(|s| s.to_lowercase() != "close")
            .unwrap_or(true); // Default to keep-alive for HTTP/1.1

        let mut stream_option: Option<TcpStream> = None;
        let mut _reused_connection = false;

        if use_keep_alive {
            self.cleanup_idle_connections();

            if let Some(entry) = self.http1_connections.get_mut(&connection_key) {
                if !entry.is_stale(self.connection_timeout) 
                    && !entry.should_close() 
                    && entry.is_healthy() {
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
            TcpStream::connect(&format!("{}:{}", host, port))?
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
                    
                    stream.write_all(request.get_body())?;
                    stream.flush()?;
                } else if status >= 400 {
                    drop(reader);
                    let reader = BufReader::new(stream);
                    return self.read_http1_response(reader, host.clone(), port, connection_key, use_keep_alive);
                }
            }
        } else {
            stream.write_all(b"\r\n")?;
            let body = request.get_body();
            if !body.is_empty() {
                stream.write_all(body)?;
            }
            stream.flush()?;
        }

        let reader = BufReader::new(stream);
        self.read_http1_response(reader, host, port, connection_key, use_keep_alive)
    }

    fn read_http1_response(&mut self, mut reader: BufReader<TcpStream>, host: String, port: u16, connection_key: String, requested_keep_alive: bool) -> Result<HttpResponse, io::Error> {
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;

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
            _ => HttpVersion::Http11,
        };

        let status_code: u16 = parts[1].parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid status code")
        })?;

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
            read_chunked_body(&mut reader)?
        } else {
            let mut body = Vec::new();
            reader.read_to_end(&mut body)?;
            body
        };

        let mut trailer_headers = HashMap::new();
        if headers.get("Transfer-Encoding").map(|s| s.as_str()) == Some("chunked") {
            loop {
                let mut line = String::new();
                reader.read_line(&mut line)?;
                if line.trim().is_empty() {
                    break;
                }

                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim().to_string();
                    let value = line[pos + 1..].trim().to_string();
                    trailer_headers.insert(key, value);
                }
            }
        }

        for (key, value) in trailer_headers {
            headers.insert(key, value);
        }

        let server_wants_close = headers.get("Connection")
            .map(|v| v.to_lowercase().contains("close"))
            .unwrap_or(false);

        let should_keep_alive = requested_keep_alive 
            && !server_wants_close 
            && version == HttpVersion::Http11
            && self.http1_connections.len() < self.max_connections_per_host;

        if should_keep_alive {
            let stream = reader.into_inner();
            let entry = Http1ConnectionEntry::new(stream, host, port);
            self.http1_connections.insert(connection_key, entry);
        }

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

        entry.connection.send_request(
            stream_id,
            headers,
            Some(request.get_body().to_vec()),
        );

        if !request.get_body().is_empty() {
            entry.connection.send_data(stream_id, request.get_body().to_vec(), true);
        }

        let response = Self::extract_http2_response(entry, stream_id)?;

        Ok(response)
    }

    fn get_or_create_http2_connection(&mut self, connection_key: &str, host: &str, port: u16) -> Result<&mut Http2ConnectionEntry, io::Error> {
        if !self.http2_connections.contains_key(connection_key) {
            let stream = TcpStream::connect(&format!("{}:{}", host, port))?;
            let connection = Http2Connection::new(stream)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create HTTP/2 connection: {:?}", e)))?;
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

    fn cleanup_idle_connections(&mut self) {
        let _now = Instant::now();
        
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
        
        let total_streams: usize = self.http2_connections
            .values()
            .map(|e| e.active_stream_count())
            .sum();
        stats.insert("active_streams".to_string(), total_streams);
        
        let max_streams: usize = self.http2_connections
            .values()
            .map(|e| e.max_concurrent_streams)
            .max()
            .unwrap_or(0);
        stats.insert("max_concurrent_streams".to_string(), max_streams);
        stats.insert("total_cookies".to_string(), self.cookie_jar.len());

        stats
    }

    pub fn connection_info(&self) -> Vec<ConnectionInfo> {
        let mut infos = Vec::new();

        // HTTP/1.1 connections
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

        // HTTP/2 connections
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
        let port = host_port[pos + 1..].parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number")
        })?;
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

    if let Ok((scheme, host, port, _)) = parse_url(base) {
        if relative.starts_with('/') {
            format!("{}://{}:{}{}", scheme, host, port, relative)
        } else {
            format!("{}://{}:{}/{}", scheme, host, port, relative)
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
        let chunk_size = usize::from_str_radix(size_str, 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid chunk size")
        })?;

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

    #[test]
    fn test_client_builder() {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("CustomAgent/1.0".to_string())
            .follow_redirects(false)
            .preferred_version(HttpVersion::Http2)
            .build();

        assert_eq!(client.timeout, Some(Duration::from_secs(60)));
        assert_eq!(client.user_agent, "CustomAgent/1.0");
        assert!(!client.follow_redirects);
        assert_eq!(client.preferred_version, HttpVersion::Http2);
    }

    #[test]
    fn test_cookie_management() {
        let mut client = HttpClient::new();
        
        let mut cookie = Cookie::new("session", "abc123");
        cookie.set_domain("example.com".to_string());
        client.add_cookie(cookie);

        assert_eq!(client.cookie_jar().len(), 1);
        assert!(client.cookie_jar().contains("session"));

        client.clear_cookies();
        assert_eq!(client.cookie_jar().len(), 0);
    }
}