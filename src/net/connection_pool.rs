use super::tcp::TcpStream;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECTION_POOL_PAYLOAD_MAGIC: &str = "SINGULARITY_CONNECTION_POOL_V1";
const CONNECTION_POOL_SNAPSHOT_MAGIC_V2: &str = "SINGULARITY_CONNECTION_POOL_SNAPSHOT_V2";
const CONNECTION_POOL_SNAPSHOT_MAGIC_LEGACY: &str = "SINGULARITY_CONNECTION_POOL_SNAPSHOT";
const CONNECTION_POOL_SNAPSHOT_CONTEXT: &str = "SINGULARITY_CONNECTION_POOL_SNAPSHOT_BINDING_V1";

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub total_hosts: usize,
    pub oldest_connection_age: Duration,
    pub total_requests_served: usize,
}

#[derive(Debug, Clone)]
pub struct PoolSnapshot {
    pub exported_unix_seconds: u64,
    pub algorithm: CompressionAlgorithm,
    pub total_connections: usize,
    pub total_hosts: usize,
    pub total_requests_served: usize,
    pub oldest_connection_age_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshotEnvelopeMeta {
    pub algorithm: CompressionAlgorithm,
    pub integrity_enabled: bool,
    pub nonce_b64: Option<String>,
    pub digest_b64: Option<String>,
    pub tag_b64: Option<String>,
    pub raw_size: Option<usize>,
    pub encoded_size: Option<usize>,
    pub issued_at_unix: Option<u64>,
    pub is_legacy: bool,
}

#[derive(Debug, Clone)]
pub struct PoolSecurityCfg {
    pub enable_integrity: bool,
    pub nonce_len: usize,
}

#[derive(Debug, Clone)]
pub struct PoolCompressionCfg {
    pub enabled: bool,
    pub algorithm: CompressionAlgorithm,
    pub level: CompressionLevel,
    pub min_size: usize,
}

struct PooledConnection {
    stream: TcpStream,
    last_used: Instant,
    request_count: usize,
    created_at: Instant,
    integrity_nonce: Vec<u8>,
    integrity_tag: String,
    lifecycle_tick: u64,
    peer_fingerprint: String,
}

pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
    max_connection_age: Duration,
    max_requests_per_connection: usize,
    security_cfg: PoolSecurityCfg,
    compression_cfg: PoolCompressionCfg,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 5,
            idle_timeout: Duration::from_secs(90),
            max_connection_age: Duration::from_secs(600),
            max_requests_per_connection: 100,
            security_cfg: PoolSecurityCfg::default(),
            compression_cfg: PoolCompressionCfg::default(),
        }
    }

    pub fn with_config(max_idle_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host,
            idle_timeout,
            max_connection_age: Duration::from_secs(600),
            max_requests_per_connection: 100,
            security_cfg: PoolSecurityCfg::default(),
            compression_cfg: PoolCompressionCfg::default(),
        }
    }

    pub fn with_limits(max_idle: usize, idle_timeout: Duration, max_age: Duration, max_requests: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: max_idle,
            idle_timeout,
            max_connection_age: max_age,
            max_requests_per_connection: max_requests,
            security_cfg: PoolSecurityCfg::default(),
            compression_cfg: PoolCompressionCfg::default(),
        }
    }

    pub fn with_security(mut self, security_cfg: PoolSecurityCfg) -> Self {
        self.security_cfg = security_cfg;
        self
    }

    pub fn with_snapshot_compression(mut self, compression_cfg: PoolCompressionCfg) -> Self {
        self.compression_cfg = compression_cfg;
        self
    }

    pub fn get_or_connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let key = Self::derive_pool_key(host, port);
        if let Some(stream) = self.try_get(&key) {
            return Ok(stream);
        }

        let addr = format!("{}:{}", host, port);
        TcpStream::connect(addr)
    }

    fn try_get(&self, key: &str) -> Option<TcpStream> {
        let mut pool = self.connections.lock().unwrap();
        if let Some(connections) = pool.get_mut(key) {
            while let Some(mut conn) = connections.pop() {
                if conn.last_used.elapsed() >= self.idle_timeout {
                    continue;
                }

                if conn.age() >= self.max_connection_age {
                    continue;
                }

                if conn.request_count >= self.max_requests_per_connection {
                    continue;
                }

                if !conn.verify_integrity(key, &self.security_cfg) {
                    continue;
                }

                conn.mark_used(key, &self.security_cfg);
                return Some(conn.stream);
            }
        }

        None
    }

    pub fn return_connection(&self, host: &str, port: u16, stream: TcpStream) {
        let key = Self::derive_pool_key(host, port);
        let mut pool = self.connections.lock().unwrap();
        let connections = pool.entry(key.clone()).or_insert_with(Vec::new);
        if connections.len() < self.max_idle_per_host {
            connections.push(PooledConnection::new(stream, &key, &self.security_cfg));
        }
    }

    pub fn clean_expired(&self) {
        let mut pool = self.connections.lock().unwrap();
        let idle_timeout = self.idle_timeout;
        let max_age = self.max_connection_age;
        let max_requests = self.max_requests_per_connection;
        let security_cfg = self.security_cfg.clone();
        for (key, connections) in pool.iter_mut() {
            connections.retain(|conn| {
                conn.last_used.elapsed() < idle_timeout && conn.age() < max_age && conn.request_count < max_requests && conn.verify_integrity(key, &security_cfg)
            });
        }

        pool.retain(|_, conns| !conns.is_empty());
    }

    pub fn clear(&self) {
        let mut pool = self.connections.lock().unwrap();
        pool.clear();
    }

    pub fn stats(&self) -> PoolStats {
        let pool = self.connections.lock().unwrap();
        let total_connections: usize = pool.values().map(|v| v.len()).sum();
        let total_hosts = pool.len();
        let mut oldest_age = Duration::from_secs(0);
        let mut total_requests = 0usize;
        for conns in pool.values() {
            for conn in conns {
                let age = conn.age();
                if age > oldest_age {
                    oldest_age = age;
                }

                total_requests += conn.request_count;
            }
        }

        PoolStats {
            total_connections,
            total_hosts,
            oldest_connection_age: oldest_age,
            total_requests_served: total_requests,
        }
    }

    pub fn connection_count(&self) -> usize {
        let pool = self.connections.lock().unwrap();
        pool.values().map(|v| v.len()).sum()
    }

    pub fn host_count(&self) -> usize {
        let pool = self.connections.lock().unwrap();
        pool.len()
    }

    pub fn export_snapshot(&self) -> io::Result<Vec<u8>> {
        let preferred = if self.compression_cfg.enabled {
            self.compression_cfg.algorithm
        } else {
            CompressionAlgorithm::Identity
        };

        self.export_snapshot_with_algorithm(preferred)
    }

    pub fn export_snapshot_auto(&self, accept_encoding: &str) -> io::Result<Vec<u8>> {
        let preferred = if self.compression_cfg.enabled {
            select_snapshot_compression_algorithm(accept_encoding)
        } else {
            CompressionAlgorithm::Identity
        };

        self.export_snapshot_with_algorithm(preferred)
    }

    fn export_snapshot_with_algorithm(&self, preferred_algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let stats = self.stats();
        let exported_unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();
        let mut payload = String::new();
        payload.push_str(CONNECTION_POOL_PAYLOAD_MAGIC);
        payload.push('\n');
        payload.push_str(&format!("exported_unix_seconds={}\n", exported_unix_seconds));
        payload.push_str(&format!("total_connections={}\n", stats.total_connections));
        payload.push_str(&format!("total_hosts={}\n", stats.total_hosts));
        payload.push_str(&format!(
            "oldest_connection_age_seconds={}\n",
            stats.oldest_connection_age.as_secs()
        ));

        payload.push_str(&format!(
            "total_requests_served={}\n",
            stats.total_requests_served
        ));

        let raw_payload = payload.into_bytes();
        let raw_size = raw_payload.len();
        let digest = sha256(&raw_payload);
        let digest_b64 = pem::encode(&digest);
        let mut encoded_payload = raw_payload;
        let mut algorithm = CompressionAlgorithm::Identity;
        if self.compression_cfg.enabled && encoded_payload.len() >= self.compression_cfg.min_size {
            let candidate = if preferred_algorithm.is_implemented() {
                preferred_algorithm
            } else if self.compression_cfg.algorithm.is_implemented() {
                self.compression_cfg.algorithm
            } else {
                CompressionAlgorithm::Identity
            };

            if candidate != CompressionAlgorithm::Identity {
                encoded_payload = compression::compress(
                    candidate,
                    &encoded_payload,
                    self.compression_cfg.level,
                )?;
                algorithm = candidate;
            }
        }

        let nonce = if self.security_cfg.enable_integrity {
            random::generate_random(self.security_cfg.nonce_len.max(8)).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to generate pool snapshot nonce: {}", e),
                )
            })?
        } else {
            Vec::new()
        };

        let tag = if self.security_cfg.enable_integrity {
            compute_snapshot_tag(&nonce, algorithm, raw_size, &encoded_payload)
        } else {
            [0u8; 32]
        };

        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nintegrity={integrity}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = CONNECTION_POOL_SNAPSHOT_MAGIC_V2,
            encoding = algorithm.content_encoding(),
            integrity = if self.security_cfg.enable_integrity { "on" } else { "off" },
            nonce = if self.security_cfg.enable_integrity {
                pem::encode(&nonce)
            } else {
                String::new()
            },
            digest = digest_b64,
            tag = if self.security_cfg.enable_integrity {
                pem::encode(&tag)
            } else {
                String::new()
            },
            raw_size = raw_size,
            encoded_size = encoded_payload.len(),
            issued_at = issued_at_unix,
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded_payload);
        Ok(out)
    }

    pub fn import_snapshot(data: &[u8]) -> io::Result<PoolSnapshot> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_snapshot_header(&header)?;
        if let Some(encoded_size) = meta.encoded_size {
            if encoded_size != body.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "snapshot encoded size mismatch: expected {}, got {}",
                        encoded_size,
                        body.len()
                    ),
                ));
            }
        }

        let should_verify_tag = meta.integrity_enabled || (meta.nonce_b64.is_some() && meta.tag_b64.is_some());
        if should_verify_tag {
            let nonce_b64 = meta.nonce_b64.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot integrity enabled but nonce is missing",
                )
            })?;

            let tag_b64 = meta.tag_b64.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot integrity enabled but tag is missing",
                )
            })?;

            let raw_size = meta.raw_size.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot integrity enabled but raw-size is missing",
                )
            })?;

            let nonce = pem::decode(&nonce_b64).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot nonce is not valid base64",
                )
            })?;

            let expected_tag = pem::decode(&tag_b64).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot tag is not valid base64",
                )
            })?;

            let computed_tag = compute_snapshot_tag(&nonce, meta.algorithm, raw_size, body);
            if !constant_time_eq(&expected_tag, &computed_tag) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot tag verification failed",
                ));
            }
        }

        let decoded_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if let Some(raw_size) = meta.raw_size {
            if raw_size != decoded_payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "snapshot raw size mismatch: expected {}, got {}",
                        raw_size,
                        decoded_payload.len()
                    ),
                ));
            }
        }

        if let Some(expected_digest_b64) = meta.digest_b64 {
            let computed_digest = sha256(&decoded_payload);
            let computed_digest_b64 = pem::encode(&computed_digest);
            if !constant_time_eq(computed_digest_b64.as_bytes(), expected_digest_b64.as_bytes()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot digest verification failed",
                ));
            }
        }

        let text = String::from_utf8(decoded_payload).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "snapshot payload is not UTF-8")
        })?;

        parse_snapshot_payload(&text, meta.algorithm)
    }

    pub fn derive_pool_key(host: &str, port: u16) -> String {
        let authority = format!("{}:{}", host, port);
        let digest = sha256(authority.as_bytes());
        format!("sha256:{}", pem::encode(&digest))
    }
}

impl PooledConnection {
    fn new(stream: TcpStream, host_key: &str, security_cfg: &PoolSecurityCfg) -> Self {
        let now = Instant::now();
        let peer_fingerprint = stream.peer_addr().ok().map(|addr| pem::encode(&sha256(addr.to_string().as_bytes())))
            .unwrap_or_else(|| "unknown-peer".to_string());

        let integrity_nonce = if security_cfg.enable_integrity {
            random::generate_random(security_cfg.nonce_len.max(8)).unwrap_or_else(|_| vec![0u8; 16])
        } else {
            Vec::new()
        };

        let lifecycle_tick = 0u64;
        let request_count = 0usize;
        let integrity_tag = Self::compute_integrity_tag(
            host_key,
            request_count,
            lifecycle_tick,
            &peer_fingerprint,
            &integrity_nonce,
            security_cfg,
        );

        Self {
            stream,
            last_used: now,
            request_count,
            created_at: now,
            integrity_nonce,
            integrity_tag,
            lifecycle_tick,
            peer_fingerprint,
        }
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn mark_used(&mut self, host_key: &str, security_cfg: &PoolSecurityCfg) {
        self.last_used = Instant::now();
        self.request_count = self.request_count.saturating_add(1);
        self.lifecycle_tick = self.lifecycle_tick.saturating_add(1);
        self.integrity_tag = Self::compute_integrity_tag(
            host_key,
            self.request_count,
            self.lifecycle_tick,
            &self.peer_fingerprint,
            &self.integrity_nonce,
            security_cfg,
        );
    }

    fn verify_integrity(&self, host_key: &str, security_cfg: &PoolSecurityCfg) -> bool {
        if !security_cfg.enable_integrity {
            return true;
        }

        let expected = Self::compute_integrity_tag(
            host_key,
            self.request_count,
            self.lifecycle_tick,
            &self.peer_fingerprint,
            &self.integrity_nonce,
            security_cfg,
        );

        constant_time_eq(expected.as_bytes(), self.integrity_tag.as_bytes())
    }

    fn compute_integrity_tag(host_key: &str, request_count: usize, lifecycle_tick: u64, peer_fingerprint: &str, nonce: &[u8], security_cfg: &PoolSecurityCfg) -> String {
        if !security_cfg.enable_integrity {
            return String::new();
        }

        let mut blob = Vec::new();
        blob.extend_from_slice(host_key.as_bytes());
        blob.extend_from_slice(b"|");
        blob.extend_from_slice(request_count.to_string().as_bytes());
        blob.extend_from_slice(b"|");
        blob.extend_from_slice(lifecycle_tick.to_string().as_bytes());
        blob.extend_from_slice(b"|");
        blob.extend_from_slice(peer_fingerprint.as_bytes());
        blob.extend_from_slice(b"|");
        blob.extend_from_slice(nonce);

        pem::encode(&sha256(&blob))
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PoolSecurityCfg {
    fn default() -> Self {
        Self {
            enable_integrity: true,
            nonce_len: 16,
        }
    }
}

impl Default for PoolCompressionCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Default,
            min_size: 256,
        }
    }
}

pub fn select_snapshot_compression_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

fn compute_snapshot_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(CONNECTION_POOL_SNAPSHOT_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    let hmac_key = sha256(&key_material);

    let mut signed = Vec::new();
    signed.extend_from_slice(CONNECTION_POOL_SNAPSHOT_MAGIC_V2.as_bytes());
    signed.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    signed.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &signed)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    let marker = b"\n\n";
    if let Some(pos) = data.windows(marker.len()).position(|w| w == marker) {
        let header_bytes = &data[..pos];
        let body = &data[pos + marker.len()..];
        let header = String::from_utf8(header_bytes.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid snapshot header encoding")
        })?;

        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "snapshot header/body delimiter not found",
    ))
}

fn parse_snapshot_header(header: &str) -> io::Result<PoolSnapshotEnvelopeMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    let is_legacy = match magic {
        CONNECTION_POOL_SNAPSHOT_MAGIC_V2 => false,
        CONNECTION_POOL_SNAPSHOT_MAGIC_LEGACY => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported snapshot envelope magic",
            ));
        }
    };

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut integrity_enabled = false;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported snapshot content encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("integrity=") {
            let val = v.trim();
            integrity_enabled = val.eq_ignore_ascii_case("on") || val.eq_ignore_ascii_case("true") || val == "1";
        } else if let Some(v) = line.strip_prefix("nonce=") {
            let val = v.trim();
            if !val.is_empty() {
                nonce_b64 = Some(val.to_string());
            }
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            let val = v.trim();
            if !val.is_empty() {
                digest_b64 = Some(val.to_string());
            }
        } else if let Some(v) = line.strip_prefix("tag=HMAC-SHA-256=") {
            let val = v.trim();
            if !val.is_empty() {
                tag_b64 = Some(val.to_string());
            }
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("issued-at=") {
            issued_at_unix = v.trim().parse::<u64>().ok();
        }
    }

    Ok(PoolSnapshotEnvelopeMeta {
        algorithm,
        integrity_enabled,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
        is_legacy,
    })
}

fn parse_snapshot_payload(payload: &str, algorithm: CompressionAlgorithm) -> io::Result<PoolSnapshot> {
    let mut lines = payload.lines();
    let payload_magic = lines.next().unwrap_or_default();
    if payload_magic != CONNECTION_POOL_PAYLOAD_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot payload magic mismatch",
        ));
    }

    let mut exported_unix_seconds = None::<u64>;
    let mut total_connections = None::<usize>;
    let mut total_hosts = None::<usize>;
    let mut total_requests_served = None::<usize>;
    let mut oldest_connection_age_seconds = None::<u64>;
    for line in lines {
        if let Some(v) = line.strip_prefix("exported_unix_seconds=") {
            exported_unix_seconds = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("total_connections=") {
            total_connections = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("total_hosts=") {
            total_hosts = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("total_requests_served=") {
            total_requests_served = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("oldest_connection_age_seconds=") {
            oldest_connection_age_seconds = v.trim().parse::<u64>().ok();
        }
    }

    Ok(PoolSnapshot {
        exported_unix_seconds: exported_unix_seconds.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing exported_unix_seconds in snapshot payload",
            )
        })?,

        algorithm,
        total_connections: total_connections.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing total_connections in snapshot payload",
            )
        })?,

        total_hosts: total_hosts.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing total_hosts in snapshot payload",
            )
        })?,

        total_requests_served: total_requests_served.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing total_requests_served in snapshot payload",
            )
        })?,
        
        oldest_connection_age_seconds: oldest_connection_age_seconds.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing oldest_connection_age_seconds in snapshot payload",
            )
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_snapshot_compression_algorithm() {
        let selected = select_snapshot_compression_algorithm("identity;q=0.1, zstd;q=1.0");
        assert_eq!(selected, CompressionAlgorithm::Zstd);

        let selected_identity = select_snapshot_compression_algorithm("identity");
        assert_eq!(selected_identity, CompressionAlgorithm::Identity);
    }

    #[test]
    fn test_export_import_snapshot_roundtrip() {
        let pool = ConnectionPool::new();
        let blob = pool.export_snapshot().expect("export must succeed");
        let snapshot = ConnectionPool::import_snapshot(&blob).expect("import must succeed");

        assert_eq!(snapshot.total_connections, 0);
        assert_eq!(snapshot.total_hosts, 0);
        assert_eq!(snapshot.total_requests_served, 0);
    }

    #[test]
    fn test_snapshot_tamper_detected() {
        let pool = ConnectionPool::new();
        let mut blob = pool.export_snapshot().expect("export must succeed");
        let last = blob.len().saturating_sub(1);
        blob[last] ^= 0x01;

        let imported = ConnectionPool::import_snapshot(&blob);
        assert!(imported.is_err());
    }

    #[test]
    fn test_snapshot_without_integrity_still_imports() {
        let pool = ConnectionPool::new().with_security(PoolSecurityCfg {
            enable_integrity: false,
            nonce_len: 0,
        });

        let blob = pool.export_snapshot().expect("export must succeed");
        let snapshot = ConnectionPool::import_snapshot(&blob).expect("import must succeed");
        assert_eq!(snapshot.total_hosts, 0);
    }
}