use crate::net::http::headers::Headers;
use crate::net::http::method::HttpMethod;
use crate::net::http::version::HttpVersion;
use std::fmt;

// ...existing code...

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