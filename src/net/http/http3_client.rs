use super::http3::{Config, Error, QuicClient};
use super::{HttpRequest, HttpResponse, HttpVersion};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HTTP3_CLIENT_PROFILE_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_CLIENT_PROFILE_BLOB_V1";
const HTTP3_CLIENT_PROFILE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_CLIENT_PROFILE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp3ClientProfileMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub struct Http3Client {
    quic: QuicClient,
    default_timeout: Duration,
    server_name_map: HashMap<SocketAddr, String>,
}

impl Http3Client {
    pub fn new() -> Self {
        Self {
            quic: QuicClient::new(Config::default()),
            default_timeout: Duration::from_secs(30),
            server_name_map: HashMap::new(),
        }
    }

    pub fn with_config(config: Config) -> Self {
        Self {
            quic: QuicClient::new(config),
            default_timeout: Duration::from_secs(30),
            server_name_map: HashMap::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.quic = self.quic.with_timeout(timeout);
        self.default_timeout = timeout;
        self
    }

    pub fn to_secure_profile_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ClientProfileMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_http3_client_profile(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate http3-client profile nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_http3_client_profile_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let nonce_b64 = pem::encode(&nonce);
        let digest_b64 = pem::encode(&digest);
        let tag_b64 = pem::encode(&tag);
        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = HTTP3_CLIENT_PROFILE_BLOB_MAGIC,
            encoding = selected_algorithm.content_encoding(),
            nonce = nonce_b64,
            digest = digest_b64,
            tag = tag_b64,
            raw_size = raw_payload.len(),
            encoded_size = encoded_payload.len(),
            issued_at = issued_at_unix,
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&encoded_payload);

        Ok((
            SecureHttp3ClientProfileMeta {
                algorithm: selected_algorithm,
                nonce_b64,
                digest_b64,
                tag_b64,
                raw_size: raw_payload.len(),
                encoded_size: encoded_payload.len(),
                issued_at_unix,
            },
            blob,
        ))
    }

    pub fn to_secure_profile_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttp3ClientProfileMeta, Vec<u8>)> {
        let selected = select_secure_http3_client_profile_algorithm(accept_encoding);
        self.to_secure_profile_blob(selected)
    }

    pub fn from_secure_profile_blob(data: &[u8]) -> io::Result<(SecureHttp3ClientProfileMeta, Http3Client)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_http3_client_profile_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "profile digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_http3_client_profile_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http3-client profile HMAC mismatch",
            ));
        }

        let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if raw_payload.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "profile raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let actual_digest = sha256(&raw_payload);
        if !constant_time_eq(&actual_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http3-client profile digest mismatch",
            ));
        }

        let client = deserialize_http3_client_profile(&raw_payload)?;
        Ok((meta, client))
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, Error> {
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
        ];

        self.send_request(addr, headers, None)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, Error> {
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());
        
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
            ("content-length".to_string(), body.len().to_string()),
        ];

        self.send_request(addr, headers, Some(body))
    }

    pub fn request(&mut self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let url = request.path();
        let (addr, path, server_name) = Self::parse_url(url)?;
        self.server_name_map.insert(addr, server_name.clone());

        let mut headers = vec![
            (":method".to_string(), request.method().as_str().to_string()),
            (":path".to_string(), path),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), server_name),
        ];

        for (name, values) in request.headers().iter() {
            for value in values {
                headers.push((name.clone(), value.clone()));
            }
        }

        let body = if request.body_bytes().is_empty() {
            None
        } else {
            Some(request.body_bytes().to_vec())
        };

        self.send_request(addr, headers, body)
    }

    fn send_request(&mut self, addr: SocketAddr, headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        if self.quic.get_connection(addr).is_none() {
            let server_name = self.server_name_map.get(&addr)
                .map(|s| s.clone())
                .ok_or_else(|| Error::InvalidOperation("Server name not found".to_string()))?;
            
            self.quic.connect_with_sni(addr, server_name)?;
        }

        let stream_id = self.quic.send_request(addr, headers, body)?;
        let response_data = self.quic.receive_response(addr, stream_id)?;

        Self::parse_response(&response_data)
    }

    fn parse_url(url: &str) -> Result<(SocketAddr, String, String), Error> {
        let url = url.trim_start_matches("https://").trim_start_matches("http://");
        
        let (host_port, path) = if let Some(pos) = url.find('/') {
            (&url[..pos], url[pos..].to_string())
        } else {
            (url, "/".to_string())
        };

        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let host = &host_port[..colon_pos];
            let port_str = &host_port[colon_pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| Error::InvalidOperation(format!("Invalid port: {}", port_str)))?;
            
            (host, port)
        } else {
            (host_port, 443u16)
        };

        let addr: SocketAddr = format!("{}:{}", host, port).parse()
            .map_err(|_| Error::InvalidOperation(format!("Invalid address: {}:{}", host, port)))?;

        Ok((addr, path, host.to_string()))
    }

    fn parse_response(data: &[u8]) -> Result<HttpResponse, Error> {
        let response_str = String::from_utf8_lossy(data);
        let mut lines = response_str.lines();

        let mut headers = HashMap::new();
        let mut status_code = 200u16;
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }

            if line.starts_with(':') {
                if line.starts_with(":status") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        status_code = value.parse().unwrap_or(200);
                    }
                }
            } else if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        let body_start = data.iter().position(|&b| b == b'\n').and_then(|pos| {
            data[pos + 1..].iter().position(|&b| b == b'\n').map(|p| pos + p + 2)
        }).unwrap_or(data.len());

        let body = if body_start < data.len() {
            data[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(HttpResponse::new(
            status_code,
            "OK".to_string(),
            HttpVersion::Http3,
            headers,
            body,
        ))
    }

    pub fn cleanup(&mut self) {
        self.quic.cleanup_closed();
    }

    pub fn connection_count(&self) -> usize {
        self.quic.connection_count()
    }
}

impl Default for Http3Client {
    fn default() -> Self {
        Self::new()
    }
}

pub fn select_secure_http3_client_profile_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_http3_client_profile(client: &Http3Client, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ClientProfileMeta, Vec<u8>)> {
    client.to_secure_profile_blob(algorithm)
}

pub fn encode_secure_http3_client_profile_auto(client: &Http3Client, accept_encoding: &str) -> io::Result<(SecureHttp3ClientProfileMeta, Vec<u8>)> {
    client.to_secure_profile_blob_auto(accept_encoding)
}

pub fn decode_secure_http3_client_profile(data: &[u8]) -> io::Result<(SecureHttp3ClientProfileMeta, Http3Client)> {
    Http3Client::from_secure_profile_blob(data)
}

fn serialize_http3_client_profile(client: &Http3Client) -> Vec<u8> {
    let mut entries: Vec<(SocketAddr, String)> = client.server_name_map.iter()
        .map(|(addr, name)| (*addr, name.clone())).collect();

    entries.sort_by(|a, b| {
        let addr_cmp = a.0.to_string().cmp(&b.0.to_string());
        if addr_cmp == std::cmp::Ordering::Equal {
            a.1.cmp(&b.1)
        } else {
            addr_cmp
        }
    });

    let mut out = String::new();
    out.push_str(&format!("default-timeout-ms={}\n", client.default_timeout.as_millis()));
    out.push_str(&format!("known-server-count={}\n", entries.len()));
    out.push_str(&format!("active-connections={}\n", client.connection_count()));
    for (idx, (addr, name)) in entries.into_iter().enumerate() {
        out.push_str(&format!("server-name-{}-addr={}\n", idx, pem::encode(addr.to_string().as_bytes())));
        out.push_str(&format!("server-name-{}-name={}\n", idx, pem::encode(name.as_bytes())));
    }

    out.into_bytes()
}

fn deserialize_http3_client_profile(raw_payload: &[u8]) -> io::Result<Http3Client> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "http3-client profile payload is not valid UTF-8",
        )
    })?;

    let mut map = HashMap::<String, String>::new();
    for line in payload.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid profile payload line '{}'", line),
            )
        })?;

        map.insert(k.trim().to_string(), v.trim().to_string());
    }

    let timeout_ms_u128 = map.get("default-timeout-ms").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing default-timeout-ms in profile payload",
        )
    })?.parse::<u128>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid default-timeout-ms"))?;

    let timeout_ms = u64::try_from(timeout_ms_u128).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "default-timeout-ms exceeds supported range",
        )
    })?;

    let known_server_count = map.get("known-server-count").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing known-server-count in profile payload",
        )
    })?.parse::<usize>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid known-server-count"))?;

    if let Some(v) = map.get("active-connections") {
        let _ = v.parse::<usize>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid active-connections"))?;
    }

    let mut client = Http3Client::new().with_timeout(Duration::from_millis(timeout_ms));
    let mut server_name_map = HashMap::new();
    for i in 0..known_server_count {
        let addr_key = format!("server-name-{}-addr", i);
        let name_key = format!("server-name-{}-name", i);

        let addr_b64 = map.get(&addr_key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing {} in profile payload", addr_key),
            )
        })?;

        let name_b64 = map.get(&name_key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing {} in profile payload", name_key),
            )
        })?;

        let addr_text = String::from_utf8(pem::decode(addr_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid address encoding in profile payload: {}", e),
            )
        })?).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded address is not valid UTF-8",
            )
        })?;

        let name_text = String::from_utf8(pem::decode(name_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid server name encoding in profile payload: {}", e),
            )
        })?).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded server name is not valid UTF-8",
            )
        })?;

        let addr: SocketAddr = addr_text.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid socket address in profile payload: {}", addr_text),
            )
        })?;

        server_name_map.insert(addr, name_text);
    }

    client.server_name_map = server_name_map;
    Ok(client)
}

fn compute_http3_client_profile_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP3_CLIENT_PROFILE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP3_CLIENT_PROFILE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "profile header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "profile header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "profile blob missing header/body separator",
    ))
}

fn parse_secure_http3_client_profile_meta(header: &str, body_len: usize) -> io::Result<SecureHttp3ClientProfileMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP3_CLIENT_PROFILE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid http3-client profile blob magic",
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
                format!("invalid profile header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", v.trim()),
                        )
                    },
                )?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")})?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")})?.to_string();
                    
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in profile blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in profile blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in profile blob")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in profile blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in profile blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in profile blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in profile blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in profile blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in profile blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "profile encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttp3ClientProfileMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_http3_client_profile_roundtrip_identity() {
        let addr_primary: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let addr_api: SocketAddr = "127.0.0.1:8443".parse().unwrap();

        let mut client = Http3Client::new().with_timeout(Duration::from_millis(4200));
        client
            .server_name_map
            .insert(addr_primary, "example.com".to_string());
        client
            .server_name_map
            .insert(addr_api, "api.example.com".to_string());

        let (meta, blob) = client
            .to_secure_profile_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure http3 profile");

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = Http3Client::from_secure_profile_blob(&blob)
            .expect("failed to decode secure http3 profile");

        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(restored.default_timeout, Duration::from_millis(4200));
        assert_eq!(
            restored.server_name_map.get(&addr_primary),
            Some(&"example.com".to_string())
        );
        assert_eq!(
            restored.server_name_map.get(&addr_api),
            Some(&"api.example.com".to_string())
        );
    }

    #[test]
    fn test_secure_http3_client_profile_roundtrip_compressed() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        let mut client = Http3Client::new().with_timeout(Duration::from_secs(12));
        client
            .server_name_map
            .insert(addr, "compressed.example".to_string());

        let (_meta, blob) = client
            .to_secure_profile_blob(CompressionAlgorithm::Gzip)
            .expect("failed to encode compressed secure http3 profile");

        let (_decoded_meta, restored) = Http3Client::from_secure_profile_blob(&blob)
            .expect("failed to decode compressed secure http3 profile");

        assert_eq!(restored.default_timeout, Duration::from_secs(12));
        assert_eq!(
            restored.server_name_map.get(&addr),
            Some(&"compressed.example".to_string())
        );
    }

    #[test]
    fn test_secure_http3_client_profile_tamper_detected() {
        let mut client = Http3Client::new();
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        client
            .server_name_map
            .insert(addr, "tamper.example".to_string());

        let (_meta, mut blob) = client
            .to_secure_profile_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure http3 profile");

        let idx = blob.len().checked_sub(1).expect("blob should not be empty");
        blob[idx] ^= 0x01;

        let result = Http3Client::from_secure_profile_blob(&blob);
        assert!(result.is_err());
    }
}