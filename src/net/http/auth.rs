use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::md5::md5_hex;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HTTP_AUTH_BLOB_MAGIC: &str = "SINGULARITY_HTTP_AUTH_BLOB_V1";
const HTTP_AUTH_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_AUTH_BLOB_BINDING_V1";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpAuthBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
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

    pub fn select_secure_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
        let accepted = compression::parse_accept_encoding(accept_encoding);
        for (algorithm, quality) in accepted {
            if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
                return algorithm;
            }
        }

        CompressionAlgorithm::Identity
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpAuthBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_authenticator(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate auth blob nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_http_auth_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let meta = SecureHttpAuthBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix,
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = HTTP_AUTH_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix,
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded_payload);
        Ok((meta, out))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttpAuthBlobMeta, Vec<u8>)> {
        let algorithm = Self::select_secure_algorithm(accept_encoding);
        self.to_secure_blob(algorithm)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttpAuthBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_auth_blob_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in auth blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in auth blob",
            )
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid tag encoding in auth blob")
        })?;

        let computed_tag = compute_http_auth_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth blob tag verification failed",
            ));
        }

        let decoded_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if decoded_payload.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "decoded auth payload size mismatch: expected {}, got {}",
                    meta.raw_size,
                    decoded_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&decoded_payload);
        if !constant_time_eq(&expected_digest, &computed_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth blob digest verification failed",
            ));
        }

        let auth = deserialize_authenticator(&decoded_payload)?;
        Ok((meta, auth))
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
                let h1 = Self::hash_with_algo(
                    &challenge.algorithm,
                    &format!("{}:{}:{}", creds.username, challenge.realm, creds.password),
                );
                Self::hash_with_algo(
                    &challenge.algorithm,
                    &format!("{}:{}:{}", h1, challenge.nonce, cnonce),
                )
            }
            "MD5" | "" => Self::hash_with_algo(
                &challenge.algorithm,
                &format!("{}:{}:{}", creds.username, challenge.realm, creds.password),
            ),
            "SHA-256" | "SHA-256-SESS" => {
                let hash = sha256(
                    format!("{}:{}:{}", creds.username, challenge.realm, creds.password)
                        .as_bytes(),
                );
                hex::encode(&hash)
            }
            algo => {
                return Err(AuthError::UnsupportedScheme(format!(
                    "Unsupported algorithm: {}",
                    algo
                )));
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
            Self::md5_hash(&format!("{}:{}:{}", ha1, challenge.nonce, ha2))
        };

        let mut auth = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            creds.username, challenge.realm, challenge.nonce, uri, response
        );

        if let Some(qop_value) = qop {
            auth.push_str(&format!(
                r#", qop={}, nc={}, cnonce="{}""#,
                qop_value, nc, cnonce
            ));
        }

        if let Some(ref opaque) = challenge.opaque {
            auth.push_str(&format!(r#", opaque="{}""#, opaque));
        }

        auth.push_str(&format!(r#", algorithm={}"#, challenge.algorithm));

        Ok(auth)
    }

    fn generate_cnonce() -> String {
        let random_bytes = random::generate_random(16).unwrap_or_else(|_| {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
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

fn serialize_authenticator(auth: &Authenticator) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push("v=1".to_string());
    lines.push(format!("nc-counter={}", auth.nc_counter));
    lines.push(format!(
        "cnonce={}",
        encode_opt_b64(auth.cnonce_cache.as_deref())
    ));

    match &auth.credentials {
        Some(creds) => {
            lines.push("has-credentials=true".to_string());
            lines.push(format!("username={}", pem::encode(creds.username.as_bytes())));
            lines.push(format!("password={}", pem::encode(creds.password.as_bytes())));
        }
        None => {
            lines.push("has-credentials=false".to_string());
            lines.push("username=".to_string());
            lines.push("password=".to_string());
        }
    }

    match &auth.last_challenge {
        Some((challenge, cached_at)) => {
            lines.push("has-last-challenge=true".to_string());
            lines.push(format!("cached-age-secs={}", cached_at.elapsed().as_secs()));

            match challenge {
                AuthChallenge::Basic { realm } => {
                    lines.push("challenge-kind=basic".to_string());
                    lines.push(format!("realm={}", pem::encode(realm.as_bytes())));
                    lines.push("nonce=".to_string());
                    lines.push("opaque=".to_string());
                    lines.push("algorithm=".to_string());
                    lines.push("qop=".to_string());
                    lines.push("domain=".to_string());
                    lines.push("stale=false".to_string());
                }
                AuthChallenge::Digest(d) => {
                    lines.push("challenge-kind=digest".to_string());
                    lines.push(format!("realm={}", pem::encode(d.realm.as_bytes())));
                    lines.push(format!("nonce={}", pem::encode(d.nonce.as_bytes())));
                    lines.push(format!("opaque={}", encode_opt_b64(d.opaque.as_deref())));
                    lines.push(format!("algorithm={}", pem::encode(d.algorithm.as_bytes())));
                    lines.push(format!("qop={}", encode_opt_list(&d.qop)));
                    lines.push(format!("domain={}", encode_opt_list(&d.domain)));
                    lines.push(format!("stale={}", d.stale));
                }
            }
        }
        None => {
            lines.push("has-last-challenge=false".to_string());
            lines.push("cached-age-secs=0".to_string());
            lines.push("challenge-kind=".to_string());
            lines.push("realm=".to_string());
            lines.push("nonce=".to_string());
            lines.push("opaque=".to_string());
            lines.push("algorithm=".to_string());
            lines.push("qop=".to_string());
            lines.push("domain=".to_string());
            lines.push("stale=false".to_string());
        }
    }

    lines.join("\n").into_bytes()
}

fn deserialize_authenticator(raw_payload: &[u8]) -> io::Result<Authenticator> {
    let payload = std::str::from_utf8(raw_payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid utf-8 in auth payload: {}", e),
        )
    })?;

    let map = parse_kv_payload(payload);
    let nc_counter = map.get("nc-counter").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let cnonce_cache = decode_opt_b64(map.get("cnonce").map(String::as_str).unwrap_or(""))?;
    let has_credentials = parse_bool(map.get("has-credentials").map(String::as_str).unwrap_or("false"))?;
    let credentials = if has_credentials {
        let username = decode_required_b64(
            map.get("username").map(String::as_str).unwrap_or(""),
            "username",
        )?;

        let password = decode_required_b64(
            map.get("password").map(String::as_str).unwrap_or(""),
            "password",
        )?;

        Some(Credentials { username, password })
    } else {
        None
    };

    let has_last_challenge = parse_bool(map.get("has-last-challenge").map(String::as_str).unwrap_or("false"))?;
    let last_challenge = if has_last_challenge {
        let kind = map.get("challenge-kind").map(String::as_str).unwrap_or("");
        let age_secs = map.get("cached-age-secs").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let cached_at = Instant::now().checked_sub(Duration::from_secs(age_secs)).unwrap_or_else(Instant::now);
        let challenge = match kind {
            "basic" => {
                let realm = decode_required_b64(
                    map.get("realm").map(String::as_str).unwrap_or(""),
                    "realm",
                )?;

                AuthChallenge::Basic { realm }
            }
            "digest" => {
                let realm = decode_required_b64(
                    map.get("realm").map(String::as_str).unwrap_or(""),
                    "realm",
                )?;

                let nonce = decode_required_b64(
                    map.get("nonce").map(String::as_str).unwrap_or(""),
                    "nonce",
                )?;

                let opaque = decode_opt_b64(map.get("opaque").map(String::as_str).unwrap_or(""))?;
                let algorithm = decode_required_b64(
                    map.get("algorithm").map(String::as_str).unwrap_or(""),
                    "algorithm",
                )?;

                let qop = decode_opt_list(map.get("qop").map(String::as_str).unwrap_or(""))?;
                let domain = decode_opt_list(map.get("domain").map(String::as_str).unwrap_or(""))?;
                let stale = parse_bool(map.get("stale").map(String::as_str).unwrap_or("false"))?;

                AuthChallenge::Digest(DigestChallenge {
                    realm,
                    nonce,
                    opaque,
                    algorithm,
                    qop,
                    domain,
                    stale,
                })
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid challenge-kind in auth payload",
                ));
            }
        };

        Some((challenge, cached_at))
    } else {
        None
    };

    Ok(Authenticator {
        credentials,
        nc_counter,
        cnonce_cache,
        last_challenge,
    })
}

fn encode_opt_b64(value: Option<&str>) -> String {
    value.map(|v| pem::encode(v.as_bytes())).unwrap_or_default()
}

fn decode_opt_b64(value: &str) -> io::Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }

    let bytes = pem::decode(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid base64 payload"))?;
    let text = String::from_utf8(bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid utf-8 payload: {}", e),
        )
    })?;

    Ok(Some(text))
}

fn decode_required_b64(value: &str, field: &str) -> io::Result<String> {
    decode_opt_b64(value)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing required field {}", field),
        )
    })
}

fn encode_opt_list(value: &Option<Vec<String>>) -> String {
    match value {
        Some(v) if !v.is_empty() => pem::encode(v.join("\n").as_bytes()),
        _ => String::new(),
    }
}

fn decode_opt_list(value: &str) -> io::Result<Option<Vec<String>>> {
    let decoded = decode_opt_b64(value)?;
    match decoded {
        Some(content) => {
            let list: Vec<String> = content.split('\n').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            if list.is_empty() {
                Ok(None)
            } else {
                Ok(Some(list))
            }
        }
        None => Ok(None),
    }
}

fn parse_kv_payload(payload: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in payload.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    map
}

fn parse_bool(v: &str) -> io::Result<bool> {
    if v.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if v.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid bool value '{}'", v),
        ))
    }
}

fn compute_http_auth_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(HTTP_AUTH_BLOB_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());

    let hmac_key = sha256(&key_material);
    hmac_sha256(&hmac_key, encoded_payload)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("auth blob header is not utf-8: {}", e),
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("auth blob header is not utf-8: {}", e),
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "auth blob is missing header separator",
    ))
}

fn parse_secure_auth_blob_meta(header: &str, body_len: usize) -> io::Result<SecureHttpAuthBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_AUTH_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid auth blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid auth blob header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", v.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid digest header"))?;
                digest_b64 = Some(parsed.to_string());
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?;

                tag_b64 = Some(parsed.to_string());
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in auth blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in auth blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in auth blob")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in auth blob header")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in auth blob header")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing tag in auth blob header"))?;
    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in auth blob header")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in auth blob header",
        )
    })?;
    
    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in auth blob header")
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "auth blob encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttpAuthBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::MissingCredentials => {
                write!(f, "No credentials provided for authentication")
            }
            AuthError::InvalidChallenge(msg) => {
                write!(f, "Invalid authentication challenge: {}", msg)
            }
            AuthError::UnsupportedScheme(scheme) => {
                write!(f, "Unsupported authentication scheme: {}", scheme)
            }
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
                assert_eq!(
                    digest.opaque,
                    Some("5ccc069c403ebaf9f0171e9517f40e41".to_string())
                );
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

    #[test]
    fn test_secure_auth_blob_roundtrip_identity() {
        let creds = Credentials::new("Mufasa", "Circle Of Life");
        let mut auth = Authenticator::with_credentials(creds);
        auth.nc_counter = 7;
        auth.cnonce_cache = Some("deadbeef".to_string());
        auth.last_challenge = Some((
            AuthChallenge::Digest(DigestChallenge {
                realm: "testrealm@host.com".to_string(),
                nonce: "nonce-123".to_string(),
                opaque: Some("opaque-456".to_string()),
                algorithm: "MD5".to_string(),
                qop: Some(vec!["auth".to_string(), "auth-int".to_string()]),
                domain: Some(vec!["/secure".to_string(), "/admin".to_string()]),
                stale: false,
            }),
            Instant::now(),
        ));

        let (meta, blob) = auth.to_secure_blob(CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_, decoded) = Authenticator::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded.nc_counter, 7);
        assert_eq!(decoded.cnonce_cache.as_deref(), Some("deadbeef"));
        assert_eq!(
            decoded.credentials.as_ref().map(|c| c.username.as_str()),
            Some("Mufasa")
        );
        assert!(decoded.last_challenge.is_some());
    }

    #[test]
    fn test_secure_auth_blob_roundtrip_gzip() {
        let creds = Credentials::new("Aladdin", "open sesame");
        let auth = Authenticator::with_credentials(creds);

        let (meta, blob) = auth.to_secure_blob(CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, decoded) = Authenticator::from_secure_blob(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(
            decoded.credentials.as_ref().map(|c| c.username.as_str()),
            Some("Aladdin")
        );
    }

    #[test]
    fn test_secure_auth_blob_tamper_detection() {
        let creds = Credentials::new("user", "pass");
        let auth = Authenticator::with_credentials(creds);
        let (_, mut blob) = auth.to_secure_blob(CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = Authenticator::from_secure_blob(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_auth_algorithm_selection() {
        let selected =
            Authenticator::select_secure_algorithm("gzip;q=1.0, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Gzip);

        let fallback = Authenticator::select_secure_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}