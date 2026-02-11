use std::io::{Read, Write};
use std::time::Duration;
use crate::net::tcp::TcpStream;
use crate::net::connection_pool::ConnectionPool;
use crate::net::http::{HttpRequest, HttpResponse, HttpMethod, headers::Headers};
use crate::net::https::tls::{TlsStream, TlsCfg, TlsError};
use crate::url::Url;

#[derive(Debug)]
pub enum HttpsError {
    Tls(TlsError),
    Io(std::io::Error),
    InvalidUrl(String),
    InvalidResponse(String),
    Timeout,
    ConnectionFailed(String),
}

#[derive(Debug, Clone)]
pub struct HttpsClientCfg {
    pub tls_cfg: TlsCfg,
    pub timeout: Duration,
    pub follow_redirect: bool,
    pub max_redirects: usize,
    pub user_agent: String,
    pub default_headers: Headers,
}

impl Default for HttpsClientCfg {
    fn default() -> Self {
        let mut default_headers = Headers::new();
        default_headers.insert("Accept", "*/*");
        default_headers.insert("Accept-Encoding", "identity");
        default_headers.insert("Connection", "keep-alive");

        HttpsClientCfg {
            tls_cfg: TlsCfg::default(),
            timeout: Duration::from_secs(30),
            follow_redirect: true,
            max_redirects: 10,
            user_agent: "Singularity/Beta-0.0.1".to_string(),
            default_headers,
        }
    }
}

pub struct HttpsClient {
    cfg: HttpsClientCfg,
    connection_pool: ConnectionPool,
}

impl HttpsClient {
    pub fn new(cfg: HttpsClientCfg) -> Self {
        HttpsClient {
            cfg,
            connection_pool: ConnectionPool::with_limits(5, Duration::from_secs(90), Duration::from_secs(600), 100),
        }
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::GET, url, None, None)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::POST, url, Some(body), None)
    }

    pub fn put(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::PUT, url, Some(body), None)
    }

    pub fn delete(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::DELETE, url, None, None)
    }

    pub fn head(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::HEAD, url, None, None)
    }

    pub fn options(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::OPTIONS, url, None, None)
    }

    pub fn patch(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request(HttpMethod::PATCH, url, Some(body), None)
    }

    pub fn request(&mut self, method: HttpMethod, url: &str, body: Option<Vec<u8>>, headers: Option<Headers>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(method, url, body, headers, 0)
    }

    fn request_with_redirects(&mut self, method: HttpMethod, url: &str, body: Option<Vec<u8>>, headers: Option<Headers>, redirect_count: usize) -> Result<HttpResponse, HttpsError> {
        if redirect_count > self.cfg.max_redirects {
            return Err(HttpsError::InvalidResponse("Maximum redirects exceeded".to_string()));
        }

        let parsed_url = Url::parse(url).map_err(|_| HttpsError::InvalidUrl(format!("Failed to parse URL: {}", url)))?;
        if parsed_url.scheme() != "https" {
            return Err(HttpsError::InvalidUrl("URL scheme must be HTTPS".to_string()));
        }

        let host = parsed_url.host().ok_or_else(|| HttpsError::InvalidUrl("URL missing host".to_string()))?;
        let port = parsed_url.port().unwrap_or(443);
        let path = if parsed_url.path().is_empty() {
            "/".to_string()
        } else {
            parsed_url.path().to_string()
        };

        let query = parsed_url.query();
        let full_path = if let Some(q) = query {
            format!("{}?{}", path, q)
        } else {
            path
        };

        let mut request = HttpRequest::new(method.clone(), &full_path);
        request.headers_mut().insert("Host", host);
        request.headers_mut().insert("User-Agent", &self.cfg.user_agent);
        for (key, value) in self.cfg.default_headers.iter() {
            if request.headers().get(key).is_none() {
                request.headers_mut().insert(key, value.join(", "));
            }
        }

        if let Some(custom_headers) = headers {
            for (key, value) in custom_headers.iter() {
                request.headers_mut().insert(key, value.join(", "));
            }
        }

        if let Some(ref body_data) = body {
            request.headers_mut().insert("Content-Length", &body_data.len().to_string());
            request.set_body(body_data.clone());
        }

        let addr = format!("{}:{}", host, port);
        let tcp_stream = self.connection_pool.get_or_connect(host, port).map_err(|e| HttpsError::ConnectionFailed(format!("Failed to connect to {}: {}", addr, e)))?;
        let timeout = self.cfg.timeout;
        tcp_stream.set_read_timeout(Some(timeout))?;
        tcp_stream.set_write_timeout(Some(timeout))?;

        let mut tls_stream = TlsStream::new_client_with_sni(tcp_stream, self.cfg.tls_cfg.clone(), host.to_string())?;
        let request_bytes = request.to_bytes(host);
        tls_stream.write_all(&request_bytes)?;
        tls_stream.flush()?;

        let response = self.read_response(&mut tls_stream)?;
        if self.cfg.follow_redirect && response.is_redirect() {
            if let Some(location) = response.header("Location") {
                if !location.is_empty() {
                    let redirect_url = if location.starts_with("http://") || location.starts_with("https://") {
                        location.to_string()
                    } else if location.starts_with('/') {
                        format!("https://{}:{}{}", host, port, location)
                    } else {
                        format!("https://{}:{}/{}", host, port, location)
                    };

                    let redirect_method = if response.status_code() == 303 {
                        HttpMethod::GET
                    } else if response.status_code() == 307 || response.status_code() == 308 {
                        method.clone()
                    } else {
                        HttpMethod::GET
                    };

                    let redirect_body = if redirect_method == HttpMethod::GET {
                        None
                    } else {
                        body.clone()
                    };

                    return self.request_with_redirects(redirect_method, &redirect_url, redirect_body, None, redirect_count + 1);
                }
            }
        }

        Ok(response)
    }

    fn read_response(&self, stream: &mut TlsStream) -> Result<HttpResponse, HttpsError> {
        let mut buffer = Vec::new();
        let mut header_end = None;
        loop {
            let mut chunk = vec![0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&chunk[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                        }
                    }

                    if let Some(end) = header_end {
                        let headers_str = String::from_utf8_lossy(&buffer[..end]);
                        if let Some(content_length) = self.parse_content_length(&headers_str) {
                            let total_expected = end + content_length;
                            if buffer.len() >= total_expected {
                                break;
                            }
                        } else if headers_str.to_lowercase().contains("transfer-encoding: chunked") {
                            if self.is_chunked_complete(&buffer[end..]) {
                                break;
                            }
                        } else if buffer.len() >= end {
                            break;
                        }
                    }
                }

                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if header_end.is_some() {
                        break;
                    }

                    continue;
                }

                Err(e) => return Err(HttpsError::Io(e)),
            }
        }

        HttpResponse::from_bytes(&buffer).map_err(|e| HttpsError::InvalidResponse(format!("Failed to parse response: {:?}", e)))
    }

    fn parse_content_length(&self, headers: &str) -> Option<usize> {
        for line in headers.lines() {
            if line.to_lowercase().starts_with("content-length:") {
                if let Some(value) = line.split(':').nth(1) {
                    return value.trim().parse().ok();
                }
            }
        }

        None
    }

    fn is_chunked_complete(&self, body: &[u8]) -> bool {
        body.windows(5).any(|w| w == b"0\r\n\r\n")
    }
}

impl Default for HttpsClient {
    fn default() -> Self {
        HttpsClient::new(HttpsClientCfg::default())
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
            HttpsError::Tls(e) => write!(f, "TLS error: {}", e),
            HttpsError::Io(e) => write!(f, "IO error: {}", e),
            HttpsError::InvalidUrl(u) => write!(f, "Invalid URL: {}", u),
            HttpsError::InvalidResponse(r) => write!(f, "Invalid response: {}", r),
            HttpsError::Timeout => write!(f, "Connection timed out"),
            HttpsError::ConnectionFailed(c) => write!(f, "Connection failed: {}", c),
        }
    }
}

impl std::error::Error for HttpsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_client_creation() {
        let client = HttpsClient::default();
        assert_eq!(client.cfg.user_agent, "Singularity/Beta-0.0.1");
        assert!(client.cfg.follow_redirect);
        assert_eq!(client.cfg.max_redirects, 10);
    }

    #[test]
    fn test_https_client_custom_config() {
        let mut config = HttpsClientCfg::default();
        config.user_agent = "CustomAgent/2.0".to_string();
        config.follow_redirect = false;
        config.max_redirects = 5;

        let client = HttpsClient::new(config);
        assert_eq!(client.cfg.user_agent, "CustomAgent/2.0");
        assert!(!client.cfg.follow_redirect);
        assert_eq!(client.cfg.max_redirects, 5);
    }

    #[test]
    fn test_invalid_url_scheme() {
        let mut client = HttpsClient::default();
        let result = client.get("http://example.com");
        assert!(result.is_err());
        if let Err(HttpsError::InvalidUrl(msg)) = result {
            assert!(msg.contains("HTTPS"));
        } else {
            panic!("Expected InvalidUrl error");
        }
    }

    #[test]
    fn test_parse_content_length() {
        let client = HttpsClient::default();
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Type: text/plain\r\n\r\n";
        let length = client.parse_content_length(headers);
        assert_eq!(length, Some(42));
    }

    #[test]
    fn test_parse_content_length_missing() {
        let client = HttpsClient::default();
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        let length = client.parse_content_length(headers);
        assert_eq!(length, None);
    }

    #[test]
    fn test_default_headers() {
        let config = HttpsClientCfg::default();
        assert_eq!(config.default_headers.get("Accept").as_deref(), Some("*/*"));
        assert_eq!(config.default_headers.get("Accept-Encoding").as_deref(), Some("identity"));
        assert_eq!(config.default_headers.get("Connection").as_deref(), Some("keep-alive"));
    }

    #[test]
    fn test_is_chunked_complete() {
        let client = HttpsClient::default();
        let complete_body = b"5\r\nhello\r\n0\r\n\r\n";
        assert!(client.is_chunked_complete(complete_body));

        let incomplete_body = b"5\r\nhello\r\n";
        assert!(!client.is_chunked_complete(incomplete_body));
    }
}