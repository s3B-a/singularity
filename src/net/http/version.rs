use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

// Methods for HttpVersions
impl HttpVersion {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "HTTP/1.0" => Some(HttpVersion::Http10),
            "HTTP/1.1" => Some(HttpVersion::Http11),
            "HTTP/2.0" | "HTTP/2" | "h2" => Some(HttpVersion::Http2),
            "HTTP/3.0" | "HTTP/3" | "h3" => Some(HttpVersion::Http3),
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

    pub fn priority(&self) -> u8 {
        match self {
            HttpVersion::Http3 => 4,
            HttpVersion::Http2 => 3,
            HttpVersion::Http11 => 2,
            HttpVersion::Http10 => 1,
        }
    }

    pub fn alpn_protocol(&self) -> Option<&'static [u8]> {
        match self {
            HttpVersion::Http2 => Some(b"h2"),
            HttpVersion::Http3 => Some(b"h3"),
            HttpVersion::Http11 => Some(b"http/1.1"),
            HttpVersion::Http10 => None,
        }
    }

    pub fn negotiate(supported: &[HttpVersion], preferred: HttpVersion) -> HttpVersion {
        if supported.contains(&preferred) {
            return preferred;
        }

        supported.iter().max_by_key(|v| v.priority()).copied().unwrap_or(HttpVersion::Http11)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn uses_quic(&self) -> bool {
        matches!(self, HttpVersion::Http3)
    }

    pub fn requires_tls(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_server_push(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_keep_alive(&self) -> bool {
        matches!(self, HttpVersion::Http11 | HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn supports_multiplexing(&self) -> bool {
        matches!(self, HttpVersion::Http2 | HttpVersion::Http3)
    }

    pub fn parse_alt_svc(alt_svc: &str) -> Vec<(HttpVersion, String, u16)> {
        let mut versions = Vec::new();
        for entry in alt_svc.split(',') {
            let entry = entry.trim();
            if let Some((proto, rest)) = entry.split_once('=') {
                let proto = proto.trim().trim_matches('"');
                let version = match proto {
                    "h3" | "h3-29" => HttpVersion::Http3,
                    "h2" => HttpVersion::Http2,
                    "http/1.1" => HttpVersion::Http11,
                    _ => continue,
                };

                // Parse host:port
                if let Some(host_port) = rest.trim().trim_matches('"').split(';').next() {
                    if let Some((host, port_str)) = host_port.rsplit_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            versions.push((version, host.to_string(), port));
                        }
                    }
                }
            }
        }
        
        versions
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