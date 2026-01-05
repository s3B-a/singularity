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