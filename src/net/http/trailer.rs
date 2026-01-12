use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead};

#[derive(Debug, Clone, Default)]
pub struct TrailerHeaders {
    headers: HashMap<String, String>,
    pub expected: Option<HashSet<String>>,
}

impl TrailerHeaders {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            expected: None,
        }
    }

    pub fn with_expected(trailer_value: &str) -> Self {
        let expected: HashSet<String> = trailer_value.split(',').map(|s| s.trim().to_lowercase()).collect();

        Self {
            headers: HashMap::new(),
            expected: Some(expected),
        }
    }

    pub fn add(&mut self, name: String, value: String) -> Result<(), io::Error> {
        let name_lower = name.to_lowercase();
        if is_forbidden_trailer_field(&name_lower) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Forbidden trailer field: {}", name),
            ));
        }

        if let Some(ref expected) = self.expected {
            if !expected.contains(&name_lower) {
                eprintln!("Warning: Unexpected trailer '{}' not in Trailer header", name);
            }
        }

        self.headers.insert(name, value);

        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn validate_expected(&self) -> Result<(), Vec<String>> {
        if let Some(ref expected) = self.expected {
            let received: HashSet<String> = self.headers.keys().map(|k| k.to_lowercase()).collect();
            let missing: Vec<String> = expected.difference(&received).cloned().collect();
            if !missing.is_empty() {
                return Err(missing);
            }
        }

        Ok(())
    }

    pub fn parse<R: BufRead>(reader: &mut R, has_trailer_header: bool, trailer_value: Option<&str>) -> Result<Self, io::Error> {
        let mut trailers = if let Some(value) = trailer_value {
            Self::with_expected(value)
        } else {
            Self::new()
        };

        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if line.trim().is_empty() || bytes_read == 0 {
                break;
            }

            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                trailers.add(name, value)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Malformed trailer line: {}", line.trim()),
                ));
            }
        }

        if has_trailer_header {
            if let Err(missing) = trailers.validate_expected() {
                for field in missing {
                    eprintln!("Warning: Expected trailer '{}' was not received", field);
                }
            }
        }

        Ok(trailers)
    }

    pub fn into_map(self) -> HashMap<String, String> {
        self.headers
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

pub fn is_forbidden_trailer_field(field_name: &str) -> bool {

    // Fields that MUST NOT appear in trailers
    const FORBIDDEN_FIELDS: &[&str] = &[

        // Transfer and content control
        "transfer-encoding",
        "content-length",
        "trailer",
        
        // Request control data
        "host",
        "cache-control",
        "expect",
        "max-forwards",
        "pragma",
        "range",
        "te",
        
        // Authentication
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
        
        // Cookies
        "cookie",
        "set-cookie",
        
        // Content negotiation
        "content-encoding",
        "content-type",
        "content-range",
        
        // Connection management
        "connection",
        "keep-alive",
        "upgrade",
        "via",
        "warning",
        
        // Conditional requests
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        
        // Age and caching
        "age",
        "expires",
        "date",
        "retry-after",
    ];

    FORBIDDEN_FIELDS.contains(&field_name)
}

/// Common trailer fields used
pub mod common {

    /// Content-MD5: Message integrity check
    pub const CONTENT_MD5: &str = "Content-MD5";
    
    /// X-Content-SHA256: SHA-256 hash of content
    pub const X_CONTENT_SHA256: &str = "X-Content-SHA256";
    
    /// X-Content-SHA512: SHA-512 hash of content
    pub const X_CONTENT_SHA512: &str = "X-Content-SHA512";
    
    /// Digest: Message digest (RFC 3230)
    pub const DIGEST: &str = "Digest";
    
    /// X-Trailer-Status: Processing status
    pub const X_TRAILER_STATUS: &str = "X-Trailer-Status";
    
    /// X-Processing-Time: Time taken to process
    pub const X_PROCESSING_TIME: &str = "X-Processing-Time";
    
    /// Server-Timing: Server timing metrics
    pub const SERVER_TIMING: &str = "Server-Timing";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_trailer_creation() {
        let mut trailers = TrailerHeaders::new();
        assert!(trailers.is_empty());
        
        trailers.add("X-Custom".to_string(), "value".to_string()).unwrap();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_forbidden_trailer_fields() {
        assert!(is_forbidden_trailer_field("transfer-encoding"));
        assert!(is_forbidden_trailer_field("content-length"));
        assert!(is_forbidden_trailer_field("host"));
        assert!(is_forbidden_trailer_field("authorization"));
        assert!(is_forbidden_trailer_field("cookie"));
        
        assert!(!is_forbidden_trailer_field("x-custom-header"));
        assert!(!is_forbidden_trailer_field("content-md5"));
        assert!(!is_forbidden_trailer_field("digest"));
    }

    #[test]
    fn test_trailer_validation_forbidden() {
        let mut trailers = TrailerHeaders::new();
        
        let result = trailers.add("Content-Length".to_string(), "100".to_string());
        assert!(result.is_err());
        assert_eq!(trailers.len(), 0);
    }

    #[test]
    fn test_trailer_with_expected() {
        let trailers = TrailerHeaders::with_expected("X-Checksum, X-Status");
        assert_eq!(trailers.expected.as_ref().unwrap().len(), 2);
        assert!(trailers.expected.as_ref().unwrap().contains("x-checksum"));
        assert!(trailers.expected.as_ref().unwrap().contains("x-status"));
    }

    #[test]
    fn test_trailer_parse() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, false, None).unwrap();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers.get("X-Checksum"), Some(&"abc123".to_string()));
        assert_eq!(trailers.get("X-Status"), Some(&"OK".to_string()));
    }

    #[test]
    fn test_trailer_parse_with_expected() {
        let data = b"X-Checksum: abc123\r\nX-Status: OK\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status")).unwrap();
        assert_eq!(trailers.len(), 2);
        assert!(trailers.validate_expected().is_ok());
    }

    #[test]
    fn test_trailer_parse_missing_expected() {
        let data = b"X-Checksum: abc123\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let trailers = TrailerHeaders::parse(&mut cursor, true, Some("X-Checksum, X-Status")).unwrap();
        assert_eq!(trailers.len(), 1);
        
        let result = trailers.validate_expected();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), vec!["x-status"]);
    }

    #[test]
    fn test_trailer_parse_forbidden_field() {
        let data = b"Content-Length: 100\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_trailer_parse_malformed() {
        let data = b"Invalid Line Without Colon\r\n\r\n";
        let mut cursor = Cursor::new(data);
        
        let result = TrailerHeaders::parse(&mut cursor, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_common_trailer_fields() {
        use super::common::*;
        
        assert!(!is_forbidden_trailer_field(CONTENT_MD5.to_lowercase().as_str()));
        assert!(!is_forbidden_trailer_field(X_CONTENT_SHA256.to_lowercase().as_str()));
        assert!(!is_forbidden_trailer_field(DIGEST.to_lowercase().as_str()));
        assert!(!is_forbidden_trailer_field(SERVER_TIMING.to_lowercase().as_str()));
    }
}