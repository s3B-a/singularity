mod parser;
mod encoder;
mod query;

pub use parser::{ParseError};
pub use encoder::{encode, decode, encode_component, decode_component};
pub use query::QueryParams;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    scheme: String,
    username: String,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl Url {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        parser::parse_url(input)
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    pub fn query_params(&self) -> QueryParams {
        QueryParams::parse(self.query.as_deref().unwrap_or(""))
    }

    pub fn set_scheme(&mut self, scheme: impl Into<String>) {
        self.scheme = scheme.into();
    }

    pub fn set_host(&mut self, host: Option<impl Into<String>>) {
        self.host = host.map(|h| h.into());
    }

    pub fn set_port(&mut self, port: Option<u16>) {
        self.port = port;
    }

    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = path.into();
    }

    pub fn set_query(&mut self, query: Option<impl Into<String>>) {
        self.query = query.map(|q| q.into());
    }

    pub fn set_fragment(&mut self, fragment: Option<impl Into<String>>) {
        self.fragment = fragment.map(|f| f.into());
    }

    pub fn join(&self, relative: &str) -> Result<Url, ParseError> {
        parser::join_urls(self, relative)
    }

    pub fn to_string(&self) -> String {
        let mut result = String::new();
        result.push_str(&self.scheme);
        result.push_str("://");

        // Username + Password (if applicable)
        if !self.username.is_empty() {
            result.push_str(&encode_component(&self.username));
            if let Some(ref pass) = self.password {
                result.push(':');
                result.push_str(&encode_component(pass));
            }

            result.push('@');
        }

        // Host
        if let Some(ref host) = self.host {
            result.push_str(host);
        }

        // Port
        if let Some(port) = self.port {
            if !self.is_default_port() {
                result.push(':');
                result.push_str(&port.to_string());
            }
        }

        // Path
        if !self.path.is_empty() {
            if !self.path.starts_with('/') {
                result.push('/');
            }

            result.push_str(&self.path);
        } else if self.host.is_some() {
            result.push('/');
        }

        // Query
        if let Some(ref query) = self.query {
            result.push('?');
            result.push_str(query);
        }

        // Fragment
        if let Some(ref fragment) = self.fragment {
            result.push('#');
            result.push_str(fragment);
        }
        
        result
    }

    fn is_default_port(&self) -> bool {
        match (self.scheme.as_str(), self.port) {
            ("http", Some(80)) => true,
            ("https", Some(443)) => true,
            ("ftp", Some(21)) => true,
            ("ws", Some(80)) => true,
            ("wss", Some(443)) => true,
            ("file", None) => true,
            _ => false,
        }
    }

    pub fn authority(&self) -> String {
        let mut result = String::new();

        // Username + Password (if applicable)
        if !self.username.is_empty() {
            result.push_str(&self.username);
            if let Some(ref pass) = self.password {
                result.push(':');
                result.push_str(pass);
            }

            result.push('@');
        }

        // host
        if let Some(ref host) = self.host {
            result.push_str(host);
        }

        // Port
        if let Some(port) = self.port {
            if !self.is_default_port() {
                result.push(':');
                result.push_str(&port.to_string());
            }
        }

        result
    }

    pub fn origin(&self) -> String {
        let mut result = String::new();
        result.push_str(&self.scheme);
        result.push_str("://");

        // Host
        if let Some(ref host) = self.host {
            result.push_str(host);
        }

        // Port
        if let Some(port) = self.port {
            if !self.is_default_port() {
                result.push(':');
                result.push_str(&port.to_string());
            }
        }

        result
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_basic() {
        let url = Url::parse("https://example.com/path").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn test_url_with_port() {
        let url = Url::parse("https://example.com:8080/path").unwrap();
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn test_url_with_query() {
        let url = Url::parse("https://example.com/path?key=value").unwrap();
        assert_eq!(url.query(), Some("key=value"));
    }

    #[test]
    fn test_url_to_string() {
        let url = Url::parse("https://example.com:8080/path?key=value#fragment").unwrap();
        let result = url.to_string();
        assert!(result.contains("https://"));
        assert!(result.contains("example.com"));
        assert!(result.contains("8080"));
        assert!(result.contains("/path"));
        assert!(result.contains("key=value"));
        assert!(result.contains("fragment"));
    }
}