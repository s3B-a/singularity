use crate::crypto::hash::md5::md5_hex;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::encoding::pem;
use crate::crypto::random;
use std::time::{Duration, Instant};
use std::fmt;

pub struct Authenticator {
    credentials: Option<Credentials>,
    nc_counter: u32,
    cnonce_cache: Option<String>,
    last_challenge: Option<(AuthChallenge, Instant)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    Basic,
    Digest,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum AuthError {
    MissingCredentials,
    InvalidChallenge(String),
    UnsupportedScheme(String),
    EncodingError(String),
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: String,
    pub qop: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    pub stale: bool,
}

#[derive(Debug, Clone)]
pub enum AuthChallenge {
    Basic { realm: String },
    Digest(DigestChallenge),
}

impl AuthChallenge {
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        let header = header.trim();
        if header.starts_with("Basic ") {
            let params = &header[6..];
            let realm = Self::extract_param(params, "realm").ok_or(AuthError::InvalidChallenge("Missing realm".to_string()))?;

            Ok(AuthChallenge::Basic { realm })
        } else if header.starts_with("Digest ") {
            let params = &header[7..];
            let realm = Self::extract_param(params, "realm").ok_or(AuthError::InvalidChallenge("Missing realm".to_string()))?;
            let nonce = Self::extract_param(params, "nonce").ok_or(AuthError::InvalidChallenge("Missing nonce".to_string()))?;
            let opaque = Self::extract_param(params, "opaque");
            let algorithm = Self::extract_param(params, "algorithm").unwrap_or("MD5".to_string());
            let qop = Self::extract_param(params, "qop").map(|q| q.split(',').map(|s| s.trim().to_string()).collect());
            let domain = Self::extract_param(params, "domain").map(|d| d.split_whitespace().map(|s| s.to_string()).collect());
            let stale = Self::extract_param(params, "stale").map(|s| s.to_lowercase() == "true").unwrap_or(false);
            
            Ok(AuthChallenge::Digest(DigestChallenge {
                realm,
                nonce,
                opaque,
                algorithm,
                qop,
                domain,
                stale,
            }))
        } else {
            Err(AuthError::UnsupportedScheme(header.to_string()))
        }
    }

    fn extract_param(params: &str, key: &str) -> Option<String> {
        let key_pattern = format!("{}=", key);
        if let Some(start) = params.find(&key_pattern) {
            let value_start = start + key_pattern.len();
            let remaining = &params[value_start..];
            if remaining.starts_with('"') {
                if let Some(end) = remaining[1..].find('"') {
                    return Some(remaining[1..=end].to_string());
                }
            } else {
                let end = remaining.find(',').unwrap_or(remaining.len());
                return Some(remaining[..end].trim().to_string());
            }
        }
        
        None
    }
    
    pub fn scheme(&self) -> AuthScheme {
        match self {
            AuthChallenge::Basic { .. } => AuthScheme::Basic,
            AuthChallenge::Digest(_) => AuthScheme::Digest,
        }
    }
}

impl Authenticator {
    pub fn new() -> Self {
        Self {
            credentials: None,
            nc_counter: 0,
            cnonce_cache: None,
            last_challenge: None,
        }
    }

    pub fn with_credentials(credentials: Credentials) -> Self {
        Self {
            credentials: Some(credentials),
            nc_counter: 0,
            cnonce_cache: None,
            last_challenge: None,
        }
    }

    pub fn set_credentials(&mut self, credentials: Credentials) {
        self.credentials = Some(credentials);
    }

    pub fn authorize(&mut self, challenge: &AuthChallenge, method: &str, uri: &str) -> Result<String, AuthError> {
        let creds = self.credentials.as_ref().ok_or(AuthError::MissingCredentials)?.clone();
        match challenge {
            AuthChallenge::Basic { .. } => self.basic_auth(&creds),
            AuthChallenge::Digest(digest) => self.digest_auth(&creds, digest, method, uri, None),
        }
    }

    pub fn authorize_with_body(&mut self, challenge: &AuthChallenge, method: &str, uri: &str, body: Option<&[u8]>) -> Result<String, AuthError> {
        let creds = self.credentials.as_ref().ok_or(AuthError::MissingCredentials)?.clone();
        match challenge {
            AuthChallenge::Basic { .. } => self.basic_auth(&creds),
            AuthChallenge::Digest(digest_challenge) => {
                self.digest_auth(&creds, digest_challenge, method, uri, body)
            }
        }
    }

    pub fn cache_challenge(&mut self, challenge: AuthChallenge) {
        self.last_challenge = Some((challenge, Instant::now()));
    }
    
    pub fn get_cached_challenge(&self, max_age: Duration) -> Option<&AuthChallenge> {
        if let Some((ref challenge, cached_at)) = self.last_challenge {
            if cached_at.elapsed() < max_age {
                return Some(challenge);
            }
        }

        None
    }

    pub fn handle_stale_nonce(&mut self, challenge: &DigestChallenge) -> bool {
        if challenge.stale {
            self.nc_counter = 0;
            self.cnonce_cache = None;
            return true;
        }

        false
    }

    pub fn validate_opaque(&self, challenge: &DigestChallenge, response_opaque: Option<&str>) -> bool {
        match (&challenge.opaque, response_opaque) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, None) => true,
            _ => false,
        }
    }

    fn basic_auth(&self, creds: &Credentials) -> Result<String, AuthError> {
        let credential_str = format!("{}:{}", creds.username, creds.password);
        let encoded = pem::encode(credential_str.as_bytes());

        Ok(format!("Basic {}", encoded))
    }

    fn digest_auth(&mut self, creds: &Credentials, challenge: &DigestChallenge, method: &str, uri: &str, body: Option<&[u8]>) -> Result<String, AuthError> {
        self.nc_counter += 1;
        let nc = format!("{:08x}", self.nc_counter);
        if self.cnonce_cache.is_none() {
            self.cnonce_cache = Some(Self::generate_cnonce());
        }

        let cnonce = self.cnonce_cache.as_ref().unwrap();
        let qop = if let Some(ref qop_options) = challenge.qop {
            if qop_options.contains(&"auth-int".to_string()) && body.is_some() {
                Some("auth-int")
            } else if qop_options.contains(&"auth".to_string()) {
                Some("auth")
            } else {
                None
            }
        } else {
            None
        };
        
        let ha1 = match challenge.algorithm.to_uppercase().as_str() {
            "MD5-SESS" => {
                let h1 = Self::hash_with_algo(&challenge.algorithm, 
                    &format!("{}:{}:{}", creds.username, challenge.realm, creds.password));
                Self::hash_with_algo(&challenge.algorithm, 
                    &format!("{}:{}:{}", h1, challenge.nonce, cnonce))
            }
            "MD5" | "" => {
                Self::hash_with_algo(&challenge.algorithm,
                    &format!("{}:{}:{}", creds.username, challenge.realm, creds.password))
            }
            "SHA-256" | "SHA-256-SESS" => {
                let hash = sha256(format!("{}:{}:{}", 
                    creds.username, challenge.realm, creds.password).as_bytes());
                hex::encode(&hash)
            }
            algo => {
                return Err(AuthError::UnsupportedScheme(
                    format!("Unsupported algorithm: {}", algo)
                ));
            }
        };
        
        let ha2 = if qop == Some("auth-int") {
            let body_hash = if let Some(body_data) = body {
                Self::md5_hash(&hex::encode(body_data))
            } else {
                Self::md5_hash("")
            };
            Self::md5_hash(&format!("{}:{}:{}", method, uri, body_hash))
        } else {
            Self::md5_hash(&format!("{}:{}", method, uri))
        };
        
        let response = if let Some(qop_value) = qop {
            Self::md5_hash(&format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, challenge.nonce, nc, cnonce, qop_value, ha2
            ))
        } else {
            Self::md5_hash(&format!(
                "{}:{}:{}",
                ha1, challenge.nonce, ha2
            ))
        };
        
        let mut auth = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            creds.username, challenge.realm, challenge.nonce, uri, response
        );
        
        if let Some(qop_value) = qop {
            auth.push_str(&format!(r#", qop={}, nc={}, cnonce="{}""#, qop_value, nc, cnonce));
        }
        
        if let Some(ref opaque) = challenge.opaque {
            auth.push_str(&format!(r#", opaque="{}""#, opaque));
        }
        
        auth.push_str(&format!(r#", algorithm={}"#, challenge.algorithm));
        
        Ok(auth)
    }

    fn generate_cnonce() -> String {
        let random_bytes = random::generate_random(16).unwrap_or_else(|_| {
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            timestamp.to_le_bytes().to_vec()
        });
        
        hex::encode(&random_bytes)
    }

    fn md5_hash(input: &str) -> String {
        md5_hex(input.as_bytes())
    }

    fn hash_with_algo(algo: &str, input: &str) -> String {
        match algo.to_uppercase().as_str() {
            "MD5" | "MD5-SESS" | "" => md5_hex(input.as_bytes()),
            "SHA-256" | "SHA-256-SESS" => {
                let hash = sha256(input.as_bytes());
                hex::encode(&hash)
            }
            _ => md5_hex(input.as_bytes()),
        }
    }

    fn validate_domain(challenge: &DigestChallenge, uri: &str) -> bool {
        if let Some(ref domains) = challenge.domain {
            domains.iter().any(|domain| uri.starts_with(domain))
        } else {
            true
        }
    }

    pub fn reset(&mut self) {
        self.nc_counter = 0;
        self.cnonce_cache = None;
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::MissingCredentials => write!(f, "No credentials provided for authentication"),
            AuthError::InvalidChallenge(msg) => write!(f, "Invalid authentication challenge: {}", msg),
            AuthError::UnsupportedScheme(scheme) => write!(f, "Unsupported authentication scheme: {}", scheme),
            AuthError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_credentials_creation() {
        let creds = Credentials::new("user", "pass");
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
    }
    
    #[test]
    fn test_parse_basic_challenge() {
        let header = r#"Basic realm="Test Realm""#;
        let challenge = AuthChallenge::parse(header).unwrap();
        
        match challenge {
            AuthChallenge::Basic { realm } => {
                assert_eq!(realm, "Test Realm");
            }
            _ => panic!("Expected Basic challenge"),
        }
    }
    
    #[test]
    fn test_parse_digest_challenge() {
        let header = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let challenge = AuthChallenge::parse(header).unwrap();
        
        match challenge {
            AuthChallenge::Digest(digest) => {
                assert_eq!(digest.realm, "testrealm@host.com");
                assert_eq!(digest.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
                assert_eq!(digest.opaque, Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()));
                assert!(digest.qop.is_some());
            }
            _ => panic!("Expected Digest challenge"),
        }
    }
    
    #[test]
    fn test_basic_auth_generation() {
        let creds = Credentials::new("Aladdin", "open sesame");
        let mut auth = Authenticator::with_credentials(creds);
        
        let challenge = AuthChallenge::Basic {
            realm: "Test".to_string(),
        };
        
        let header = auth.authorize(&challenge, "GET", "/").unwrap();
        assert!(header.starts_with("Basic "));
    }
    
    #[test]
    fn test_digest_auth_generation() {
        let creds = Credentials::new("Mufasa", "Circle Of Life");
        let mut auth = Authenticator::with_credentials(creds);
        
        let challenge = AuthChallenge::Digest(DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            algorithm: "MD5".to_string(),
            qop: Some(vec!["auth".to_string()]),
            domain: None,
            stale: false,
        });
        
        let header = auth.authorize(&challenge, "GET", "/dir/index.html").unwrap();
        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"Mufasa\""));
        assert!(header.contains("realm=\"testrealm@host.com\""));
    }
    
    #[test]
    fn test_authenticator_reset() {
        let mut auth = Authenticator::new();
        auth.nc_counter = 5;
        auth.cnonce_cache = Some("test".to_string());
        
        auth.reset();
        
        assert_eq!(auth.nc_counter, 0);
        assert!(auth.cnonce_cache.is_none());
    }
    
    #[test]
    fn test_missing_credentials() {
        let mut auth = Authenticator::new();
        let challenge = AuthChallenge::Basic {
            realm: "Test".to_string(),
        };
        
        let result = auth.authorize(&challenge, "GET", "/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::MissingCredentials));
    }
}