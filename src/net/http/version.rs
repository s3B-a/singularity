use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

// Methods for HttpVersions
impl HttpVersion {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "HTTP/1.0" => Some(HttpVersion::Http10),
            "HTTP/1.1" => Some(HttpVersion::Http11),
            "HTTP/2" | "HTTP/2.0" => Some(HttpVersion::Http2),
            "HTTP/3" | "HTTP/3.0" => Some(HttpVersion::Http3),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2.0",
            HttpVersion::Http3 => "HTTP/3.0",
        }
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn uses_quic(&self) -> bool {
        matches!(self, HttpVersion::Http3)
    }

    pub fn supports_server_push(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_multiplexing(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for HttpVersion {
    fn default() -> Self {
        HttpVersion::Http11
    }
}