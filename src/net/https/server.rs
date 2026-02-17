use super::tls::{TlsStream, TlsCfg};
use crate::net::http::{HttpRequest, HttpResponse, HttpMethod, HttpVersion};
use crate::net::tcp::{TcpListener, TcpStream};
use crate::net::http::http2::alpn::AlpnProtocol;
use crate::net::http::http2::Http2Connection;
use std::io::{Read, Write, BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

pub type HttpsHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

#[derive(Clone, Debug)]
pub struct HttpsServerCfg {
    pub tls_config: TlsCfg,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub max_body_size: usize,
    pub keep_alive: bool,
    pub keep_alive_timeout: Duration,
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
        let listener = self.listener.take().ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Server not bound to an address"
        ))?;

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
                            eprintln!("TLS Connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn start_async(&mut self) -> std::io::Result<thread::JoinHandle<std::io::Result<()>>> {
        let listener = self.listener.take().ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Server not bound to an address"
        ))?;

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
                                eprintln!("TLS Connection error from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
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
        let mut tls_stream = TlsStream::new_server(stream, config.tls_config.clone()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tls_stream.set_read_timeout(Some(config.request_timeout)).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tls_stream.set_write_timeout(Some(config.request_timeout)).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let cloned_stream = tls_stream.try_clone().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut reader = BufReader::new(cloned_stream);
        loop {
            match Self::parse_request(&mut reader, &config) {
                Ok(request) => {
                    let response = if let Some(ref h) = handler {
                        h(&request)
                    } else {
                        Self::default_handler(&request)
                    };

                    let response_bytes = Self::serialize_response(&response);
                    tls_stream.write_all(&response_bytes)?;
                    tls_stream.flush()?;
                    if !config.keep_alive || request.headers().get("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false) {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error parsing request from {}: {}", peer_addr, e);
                    let err_response = Self::error_response(400, "Bad Request");
                    let response_bytes = Self::serialize_response(&err_response);
                    let _ = tls_stream.write_all(&response_bytes);
                    break;
                }
            }
        }

        Ok(())
    }

    fn handle_connection_with_alpn(stream: TcpStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        let mut tls_stream =
            TlsStream::new_server(stream, config.tls_config.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let negotiated_protocol = tls_stream.get_negotiated_protocol();

        tls_stream
            .set_read_timeout(Some(config.request_timeout))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tls_stream
            .set_write_timeout(Some(config.request_timeout))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        match negotiated_protocol {
            Some(AlpnProtocol::Http2) => {
                Self::handle_http2_connection(tls_stream, peer_addr, config, handler)
            }
            Some(AlpnProtocol::Http11) | None => {
                Self::handle_http1_connection(tls_stream, peer_addr, config, handler)
            }
            _ => {
                eprintln!(
                    "Unsupported protocol negotiated for {}",
                    peer_addr
                );
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unsupported protocol",
                ))
            }
        }
    }

    fn handle_http2_connection(tls_stream: TlsStream, peer_addr: SocketAddr, config: HttpsServerCfg, handler: Option<HttpsHandler>) -> std::io::Result<()> {
        let tcp_stream = tls_stream.stream_into_inner()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut http2_conn = Http2Connection::new_with_alpn(tcp_stream, Some(AlpnProtocol::Http2))
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create HTTP/2 connection: {}", e),
            ))?;

        http2_conn.handshake_with_alpn(Some(AlpnProtocol::Http2))
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP/2 handshake failed: {}", e),
            ))?;

        loop {
            if http2_conn.goaway_received {
                eprintln!("HTTP/2 GOAWAY received from peer {}", peer_addr);
                break;
            }

            match http2_conn.receive_frames() {
                Ok(_) => {
                    if let Err(e) = Self::process_http2_streams(&mut http2_conn, &handler, peer_addr) {
                        eprintln!("Error processing HTTP/2 streams: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    if e.to_string().contains("would block") {
                        if let Err(e) = http2_conn.send_pending_data() {
                            eprintln!("Error sending pending HTTP/2 data: {}", e);
                            break;
                        }
                        
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    
                    eprintln!("HTTP/2 frame receive error: {}", e);
                    break;
                }
            }
        }

        if let Err(e) = http2_conn.close() {
            eprintln!("Error closing HTTP/2 connection: {}", e);
        }

        Ok(())
    }

    fn process_http2_streams(http2_conn: &mut Http2Connection, handler: &Option<HttpsHandler>, peer_addr: SocketAddr) -> std::io::Result<()> {
        let stream_ids: Vec<u32> = http2_conn.streams.keys().cloned().collect();
        for stream_id in stream_ids {
            let (method, path, request_headers) = {
                let stream = match http2_conn.get_stream(stream_id) {
                    Some(s) => s,
                    None => continue,
                };

                if !stream.headers_received {
                    continue;
                }

                let headers = stream.response_headers().to_vec();
                let method = headers
                    .iter()
                    .find(|(name, _)| name == ":method")
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| "GET".to_string());

                let path = headers
                    .iter()
                    .find(|(name, _)| name == ":path")
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| "/".to_string());

                (method, path, headers)
            };

            let http_method = match HttpMethod::from_str(&method) {
                Some(m) => m,
                None => {
                    eprintln!("Invalid HTTP method: {}", method);
                    continue;
                }
            };

            let mut request = HttpRequest::new(http_method, &path);
            for (name, value) in request_headers {
                if !name.starts_with(':') {
                    request.set_header(name, value);
                }
            }

            let stream = http2_conn.get_stream(stream_id).unwrap();
            let body_data = stream.data().to_vec();
            if !body_data.is_empty() {
                request.set_body(body_data);
            }

            let response = if let Some(h) = handler {
                h(&request)
            } else {
                Self::default_h2_handler(&request)
            };

            if let Err(e) = Self::send_http2_response(http2_conn, stream_id, &response) {
                eprintln!(
                    "Error sending HTTP/2 response for stream {}: {}",
                    stream_id, e
                );
            }

            if let Err(e) = http2_conn.close_stream(stream_id) {
                eprintln!("Error closing stream {}: {}", stream_id, e);
            }
        }

        Ok(())
    }

    fn send_http2_response(http2_conn: &mut Http2Connection, stream_id: u32, response: &HttpResponse) -> std::io::Result<()> {
        let mut headers = vec![
            (":status".to_string(), response.status_code().to_string()),
        ];

        for (key, value) in response.headers() {
            headers.push((key.clone(), value.clone()));
        }

        if !response.body().is_empty() {
            headers.push((
                "content-length".to_string(),
                response.body().len().to_string(),
            ));
        }

        http2_conn
            .send_request(stream_id, headers, Some(response.body().to_vec()))
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP/2 send request failed: {}", e),
            ))
    }

    fn default_h2_handler(request: &HttpRequest) -> HttpResponse {
        let body = format!(
            r#"{{
  "status": "404",
  "message": "Not Found",
  "path": "{}",
  "method": "{}"
}}"#,
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

                    let response_bytes = Self::serialize_response(&response);
                    tls_stream.write_all(&response_bytes)?;
                    tls_stream.flush()?;

                    if !config.keep_alive
                        || request
                            .headers()
                            .get("Connection")
                            .map(|v| v.to_lowercase().contains("close"))
                            .unwrap_or(false)
                    {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error parsing request from {}: {}", peer_addr, e);
                    let err_response = Self::error_response(400, "Bad Request");
                    let response_bytes = Self::serialize_response(&err_response);
                    let _ = tls_stream.write_all(&response_bytes);
                    break;
                }
            }
        }

        Ok(())
    }

    fn parse_request(reader: &mut BufReader<TlsStream>, config: &HttpsServerCfg) -> std::io::Result<HttpRequest> {
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unknown HTTP method",
                ))
            }
        };

        let path = parts[1].to_string();
        let version = match parts[2] {
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

                if key.to_lowercase() == "content-length" {
                    content_length = value.parse().unwrap_or(0);
                }

                headers.insert(key, value);
            }
        }

        let mut body = Vec::new();
        if content_length > 0 {
            if content_length > config.max_body_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Request body too large",
                ));
            }

            body.resize(content_length, 0);
            reader.read_exact(&mut body)?;
        }

        let mut request = HttpRequest::new(method, &path);
        for (key, value) in headers {
            request.set_header(key, value);
        }

        request.set_body(body);

        Ok(request)
    }

    fn serialize_response(response: &HttpResponse) -> Vec<u8> {
        let mut result = Vec::new();
        let status_line = format!("{} {} {}\r\n", response.version().as_str(), response.status_code(), response.reason_phrase());
        result.extend_from_slice(status_line.as_bytes());
        for (key, value) in response.headers() {
            result.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        if response.headers().get("Content-Length").is_none() && !response.body().is_empty() {
            result.extend_from_slice(format!("Content-Length: {}\r\n", response.body().len()).as_bytes());
        }

        result.extend_from_slice(b"\r\n");
        result.extend_from_slice(response.body());

        result
    }

    fn default_handler(request: &HttpRequest) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>Path: {}</p></body></html>",
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

    fn error_response(status_code: u16, reason_phrase: &str) -> HttpResponse {
        let body = format!(
            "<!DOCTYPE html><html><body><h1>{} {}</h1></body></html>",
            status_code, reason_phrase
        );

        HttpResponse::new(
            status_code,
            reason_phrase.to_string(),
            HttpVersion::Http11,
            {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "text/html".to_string());
                headers
            },
            body.into_bytes(),
        )
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
}