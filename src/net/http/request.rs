use crate::net::http::headers::Headers;
use crate::net::http::method::HttpMethod;
use crate::net::http::version::HttpVersion;
use std::fmt;

#[derive(Clone)]
pub struct HttpRequest {
    method: HttpMethod,
    path: String,
    version: HttpVersion,
    headers: Headers,
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            version: HttpVersion::default(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn set_body(&mut self, body: impl Into<Vec<u8>>) {
        self.body = body.into();
        self.headers.insert("Content-Length", self.body.len().to_string());
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name, value);
    }

    pub fn get_body(&self) -> &[u8] {
        &self.body
    }

    pub fn clone(&self) -> Self {
        Self {
            method: self.method,
            path: self.path.clone(),
            version: self.version,
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }

    pub fn build(&self, host: &str) -> Vec<u8> {
        let mut request = String::new();
        request.push_str(&format!(
            "{} {} {}\r\n",
            self.method.as_str(), self.path, self.version.as_str()
        ));

        let mut headers = self.headers.clone();
        if !headers.contains("Host") {
            headers.insert("Host", host);
        }

        if !headers.contains("User-Agent") {
            headers.insert("User-Agent", "Singularity/0.0.1");
        }

        if !headers.contains("accept") {
            headers.insert("Accept", "*/*");
        }

        if !headers.contains("Connection") {
            headers.insert("Connection", "Keep-Alive");
        }

        if !self.body.is_empty() && !headers.contains("Content-Length") {
            headers.insert("Content-Length", self.body.len().to_string());
        }

        request.push_str(&headers.format());
        request.push_str("\r\n");

        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }

    pub fn to_bytes(&self, host: &str) -> Vec<u8> {
        self.build(host)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let request_str = std::str::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {}", e))?;
        let header_end = request_str.find("\r\n\r\n").ok_or_else(|| "No header terminator found".to_string())?;
        let header_section = &request_str[..header_end];
        let body_start = header_end + 4;
        let mut lines = header_section.lines();
        let request_line = lines.next().ok_or_else(|| "Empty request".to_string())?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(format!("Invalid request line: {}", request_line));
        }

        let method = HttpMethod::from_str(parts[0]).ok_or_else(|| format!("Invalid HTTP method: {}", parts[0]))?;
        let path = parts[1].to_string();
        let version = HttpVersion::from_str(parts[2]).ok_or_else(|| format!("Invalid HTTP version: {}", parts[2]))?;
        let mut headers = Headers::new();
        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.insert(name, value);
            } else {
                return Err(format!("Invalid header line: {}", line));
            }
        }

        let body = if body_start < bytes.len() {
            bytes[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            method,
            path,
            version,
            headers,
            body,
        })
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body_length", &self.body.len())
            .finish()
    }
}

pub struct RequestBuilder {
    request: HttpRequest,
}

impl RequestBuilder {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            request: HttpRequest::new(method, path),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request = self.request.body(body);
        self
    }

    pub fn build(self) -> HttpRequest {
        self.request
    }
}