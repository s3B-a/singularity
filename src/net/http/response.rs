use super::version::HttpVersion;
use std::collections::HashMap;

pub struct HttpResponse {
    status_code: u16,
    reason_phrase: String,
    version: HttpVersion,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(
        status_code: u16,
        reason_phrase: String,
        version: HttpVersion,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status_code,
            reason_phrase,
            version,
            headers,
            body,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn reason_phrase(&self) -> &str {
        &self.reason_phrase
    }

    pub fn version(&self) -> HttpVersion {
        self.version
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    pub fn header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = String::new();
        response.push_str(&format!(
            "{} {} {}\r\n",
            self.version.as_str(),
            self.status_code,
            self.reason_phrase
        ));

        for (key, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }

        if !self.body.is_empty() && !self.headers.contains_key("Content-Length") {
            response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }

        response.push_str("\r\n");
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let header_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "No header terminator found".to_string())?;
        let header_section = &bytes[..header_end];
        let body_start = header_end + 4;
        let header_str = std::str::from_utf8(header_section).map_err(|e| format!("Invalid UTF-8 in headers: {}", e))?;
        let mut lines = header_str.lines();
        let status_line = lines.next().ok_or_else(|| "Empty response".to_string())?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid status line: {}", status_line));
        }

        let version = HttpVersion::from_str(parts[0]).ok_or_else(|| format!("Invalid HTTP version: {}", parts[0]))?;
        let status_code = parts[1].parse::<u16>().map_err(|_| format!("Invalid status code: {}", parts[1]))?;
        let reason_phrase = if parts.len() == 3 {
            parts[2].to_string()
        } else {
            Self::default_reason_phrase(status_code)
        };

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            } else {
                return Err(format!("Invalid header line: {}", line));
            }
        }

        let body = if body_start < bytes.len() {
            if let Some(content_length_str) = headers.get("Content-Length") {
                let content_length = content_length_str.parse::<usize>().map_err(|_| format!("Invalid Content-Length: {}", content_length_str))?;
                let body_end = body_start + content_length;
                if body_end > bytes.len() {
                    return Err(format!(
                        "Content-Length ({}) exceeds available data ({})",
                        content_length,
                        bytes.len() - body_start
                    ));
                }
                bytes[body_start..body_end].to_vec()
            } else if headers.get("Transfer-Encoding").map(|s| s.as_str()) == Some("chunked") {
                Self::decode_chunked(&bytes[body_start..])?
            } else {
                bytes[body_start..].to_vec()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            status_code,
            reason_phrase,
            version,
            headers,
            body,
        })
    }

    fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let mut pos = 0;
        loop {
            let size_line_end = data[pos..].windows(2).position(|w| w == b"\r\n")
                .ok_or_else(|| "Malformed chunked encoding: no CRLF after chunk size".to_string())?;

            let size_str = std::str::from_utf8(&data[pos..pos + size_line_end]).map_err(|_| "Invalid UTF-8 in chunk size".to_string())?;
            let size_part = size_str.split(';').next().unwrap().trim();
            let chunk_size = usize::from_str_radix(size_part, 16).map_err(|_| format!("Invalid chunk size: {}", size_part))?;

            pos += size_line_end + 2;
            if chunk_size == 0 {
                break;
            }

            if pos + chunk_size > data.len() {
                return Err("Chunk size exceeds available data".to_string());
            }

            result.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size;
            if pos + 2 > data.len() || &data[pos..pos + 2] != b"\r\n" {
                return Err("Missing CRLF after chunk data".to_string());
            }

            pos += 2;
        }

        Ok(result)
    }

    fn default_reason_phrase(status_code: u16) -> String {
        match status_code {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
        .to_string()
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status_code", &self.status_code)
            .field("reason_phrase", &self.reason_phrase)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}