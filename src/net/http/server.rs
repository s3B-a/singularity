use super::{HttpRequest, HttpResponse, HttpMethod, HttpVersion};
use crate::net::tcp::{TcpListener, TcpStream};
use std::io::{Read, BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

pub type HttpHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

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
            "Server not bound to an address",
        ))?;

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
                Err(e) if e.kind() != std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
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
            "Server not bound to an address",
        ))?;

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
                    Err(e) if e.kind() != std::io::ErrorKind::WouldBlock => {
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

    fn handle_connection(mut stream: TcpStream, _peer_addr: SocketAddr, config: HttpServerCfg, handler: Option<HttpHandler>) -> std::io::Result<()> {
        stream.set_read_timeout(Some(config.request_timeout))?;
        stream.set_write_timeout(Some(config.request_timeout))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        loop {
            match Self::parse_request(&mut reader, &config) {
                Ok(request) => {
                    let response = if let Some(ref h) = handler {
                        h(&request)
                    } else {
                        Self::default_handler(&request)
                    };

                    let response_bytes = Self::serialize_response(&response);
                    stream.write_all(&response_bytes)?;
                    stream.flush()?;
                    if !config.keep_alive 
                    || request.headers().get("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false)
                    || response.headers().get("Connection").map(|v| v.to_lowercase().contains("close")).unwrap_or(false) {
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

    fn parse_request(reader: &mut BufReader<TcpStream>, config: &HttpServerCfg) -> std::io::Result<HttpRequest> {
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
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported HTTP method",
            )),
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

        let mut request = HttpRequest::new(method, path);
        for (key, value) in headers {
            request.headers_mut().insert(key, value);
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
}