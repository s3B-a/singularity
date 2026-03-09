use super::http3::{QuicClient, Config, Error, StreamId, ConnectionId};
use super::{HttpRequest, HttpResponse, HttpMethod, HttpVersion};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

pub struct Http3Client {
    quic: QuicClient,
    default_timeout: Duration,
    server_name_map: HashMap<SocketAddr, String>,
}

impl Http3Client {
    pub fn new() -> Self {
        Self {
            quic: QuicClient::new(Config::default()),
            default_timeout: Duration::from_secs(30),
            server_name_map: HashMap::new(),
        }
    }

    pub fn with_config(config: Config) -> Self {
        Self {
            quic: QuicClient::new(config),
            default_timeout: Duration::from_secs(30),
            server_name_map: HashMap::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.quic = self.quic.with_timeout(timeout);
        self.default_timeout = timeout;
        self
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, Error> {
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
        ];

        self.send_request(addr, headers, None)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error> {
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());
        
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
            ("content-length".to_string(), body.len().to_string()),
        ];

        self.send_request(addr, headers, Some(body))
    }

    pub fn request(&mut self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let url = request.path();
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());
        
        let mut headers = vec![
            (":method".to_string(), request.method().as_str().to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
        ];

        for (name, values) in request.headers().iter() {
            for value in values {
                headers.push((name.clone(), value.clone()));
            }
        }

        let body = if request.body_bytes().is_empty() {
            None
        } else {
            Some(request.body_bytes().to_vec())
        };

        self.send_request(addr, headers, body)
    }

    fn send_request(&mut self, addr: SocketAddr, headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        if self.quic.get_connection(addr).is_none() {
            let server_name = self.server_name_map.get(&addr)
                .map(|s| s.clone())
                .ok_or_else(|| Error::InvalidOperation("Server name not found".to_string()))?;
            
            self.quic.connect_with_sni(addr, server_name)?;
        }

        let stream_id = self.quic.send_request(addr, headers, body)?;
        let response_data = self.quic.receive_response(addr, stream_id)?;

        Self::parse_response(&response_data)
    }

    fn parse_url(url: &str) -> Result<(SocketAddr, String, String), Error> {
        let url = url.trim_start_matches("https://").trim_start_matches("http://");
        
        let (host_port, path) = if let Some(pos) = url.find('/') {
            (&url[..pos], url[pos..].to_string())
        } else {
            (url, "/".to_string())
        };

        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let host = &host_port[..colon_pos];
            let port_str = &host_port[colon_pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| Error::InvalidOperation(format!("Invalid port: {}", port_str)))?;
            (host, port)
        } else {
            (host_port, 443u16)
        };

        let addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|_| Error::InvalidOperation(format!("Invalid address: {}:{}", host, port)))?;

        Ok((addr, path, host.to_string()))
    }

    fn parse_response(data: &[u8]) -> Result<HttpResponse, Error> {
        let response_str = String::from_utf8_lossy(data);
        let mut lines = response_str.lines();

        let mut headers = HashMap::new();
        let mut status_code = 200u16;

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }

            if line.starts_with(':') {
                if line.starts_with(":status") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        status_code = value.parse().unwrap_or(200);
                    }
                }
            } else if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        let body_start = data.iter().position(|&b| b == b'\n')
            .and_then(|pos| data[pos + 1..].iter().position(|&b| b == b'\n').map(|p| pos + p + 2))
            .unwrap_or(data.len());

        let body = if body_start < data.len() {
            data[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(HttpResponse::new(
            status_code,
            "OK".to_string(),
            HttpVersion::Http3,
            headers,
            body,
        ))
    }

    pub fn cleanup(&mut self) {
        self.quic.cleanup_closed();
    }

    pub fn connection_count(&self) -> usize {
        self.quic.connection_count()
    }
}

impl Default for Http3Client {
    fn default() -> Self {
        Self::new()
    }
}