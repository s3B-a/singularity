use super::cache::{CacheStats, DnsCache};
use super::query::DnsQuery;
use super::record::{DnsRecord, RecordType};
use super::response::DnsResponse;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const RESOLVER_PROFILE_MAGIC: &str = "SINGULARITY_DNS_RESOLVER_PROFILE_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureResolverProfileMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
}

pub struct DnsResolver {
    cache: DnsCache,
    servers: Arc<RwLock<Vec<SocketAddr>>>,
    pub timeout: Duration,
    pub retries: usize,
    pub enable_cache: bool,
    pub accept_encoding: String,
    pub prefer_secure_queries: bool,
    pub secure_fallback_to_plain: bool,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            cache: DnsCache::new(1024),
            servers: Arc::new(RwLock::new(Self::default_servers())),
            timeout: Duration::from_secs(5),
            retries: 3,
            enable_cache: true,
            accept_encoding: "br, zstd, gzip, deflate, identity".to_string(),
            prefer_secure_queries: false,
            secure_fallback_to_plain: true,
        }
    }

    fn default_servers() -> Vec<SocketAddr> {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(84, 200, 69, 80)), 53), // DNS.WATCH
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(84, 200, 70, 40)), 53), // DNS.WATCH
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(91, 239, 100, 100)), 53), // UncensoredDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(89, 233, 43, 71)), 53), // UncensoredDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),      // Quad9
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53), // Quad9
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(193, 138, 219, 74)), 53), // MullvadDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(193, 138, 218, 74)), 53), // MullvadDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)), 53), // AdGuardDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)), 53), // AdGuardDNS
        ]
    }

    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            cache: DnsCache::new(1024),
            servers: Arc::new(RwLock::new(servers)),
            timeout: Duration::from_secs(5),
            retries: 3,
            enable_cache: true,
            accept_encoding: "br, zstd, gzip, deflate, identity".to_string(),
            prefer_secure_queries: false,
            secure_fallback_to_plain: true,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_cache(mut self, enable: bool) -> Self {
        self.enable_cache = enable;
        self
    }

    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache = DnsCache::new(size);
        self
    }

    pub fn with_accept_encoding(mut self, accept_encoding: impl Into<String>) -> Self {
        self.accept_encoding = accept_encoding.into();
        self
    }

    pub fn with_secure_queries(mut self, enabled: bool) -> Self {
        self.prefer_secure_queries = enabled;
        self
    }

    pub fn with_secure_fallback(mut self, enabled: bool) -> Self {
        self.secure_fallback_to_plain = enabled;
        self
    }

    pub fn add_server(&self, server: SocketAddr) {
        let mut servers = self.servers.write().unwrap();
        if !servers.contains(&server) {
            servers.push(server);
        }
    }

    pub fn set_servers(&self, servers: Vec<SocketAddr>) {
        let mut s = self.servers.write().unwrap();
        *s = servers;
    }

    pub fn get_servers(&self) -> Vec<SocketAddr> {
        self.servers.read().unwrap().clone()
    }

    pub fn resolve(&self, name: &str, record_type: RecordType) -> io::Result<Vec<DnsRecord>> {
        if self.enable_cache {
            if let Some(records) = self.cache.get(name, record_type) {
                return Ok(records);
            }
        }

        let servers = self.get_servers();
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No DNS servers configured",
            ));
        }

        let mut query = self.build_query();
        let packet = query.query_with_retries(name, record_type, &servers, self.retries)?;
        let response = DnsResponse::new(packet);
        if !response.is_successful() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("DNS query failed: {:?}", response.response_code()),
            ));
        }

        let records = response.answers().to_vec();
        if self.enable_cache && !records.is_empty() {
            self.cache.insert_many(name, records.clone());
        }

        Ok(records)
    }

    pub fn resolve_secure(&self, name: &str, record_type: RecordType, algorithm: CompressionAlgorithm) -> io::Result<Vec<DnsRecord>> {
        if self.enable_cache {
            if let Some(records) = self.cache.get(name, record_type) {
                return Ok(records);
            }
        }

        let servers = self.get_servers();
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No DNS servers configured",
            ));
        }

        let mut last_error = None;
        let mut query = self.build_query();
        for _ in 0..self.retries {
            for &server in &servers {
                match query.query_secure(name, record_type, server, algorithm) {
                    Ok(packet) => {
                        let response = DnsResponse::new(packet);
                        if !response.is_successful() {
                            last_error = Some(io::Error::new(
                                io::ErrorKind::Other,
                                format!(
                                    "DNS query failed with response code: {:?}",
                                    response.response_code()
                                ),
                            ));
                            continue;
                        }

                        let records = response.answers().to_vec();
                        if self.enable_cache && !records.is_empty() {
                            self.cache.insert_many(name, records.clone());
                        }

                        return Ok(records);
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Secure DNS query failed with no specific error",
            )
        }))
    }

    pub fn resolve_ipv4(&self, name: &str) -> io::Result<Vec<Ipv4Addr>> {
        let records = self.resolve(name, RecordType::A)?;
        let mut addresses = Vec::new();
        for record in records {
            if let super::record::RecordData::A(ip) = record.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No A records found",
            ));
        }

        Ok(addresses)
    }

    pub fn resolve_ipv6(&self, name: &str) -> io::Result<Vec<Ipv6Addr>> {
        let records = self.resolve(name, RecordType::AAAA)?;
        let mut addresses = Vec::new();
        for record in records {
            if let super::record::RecordData::AAAA(ip) = record.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No AAAA records found",
            ));
        }

        Ok(addresses)
    }

    pub fn resolve_host(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();
        if let Ok(ipv4_addrs) = self.resolve_ipv4(name) {
            addresses.extend(ipv4_addrs.into_iter().map(IpAddr::V4));
        }

        if let Ok(ipv6_addrs) = self.resolve_ipv6(name) {
            addresses.extend(ipv6_addrs.into_iter().map(IpAddr::V6));
        }

        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No IP addresses found",
            ));
        }

        Ok(addresses)
    }

    pub fn resolve_cname(&self, name: &str) -> io::Result<String> {
        let records = self.resolve(name, RecordType::CNAME)?;
        for record in records {
            if let super::record::RecordData::CNAME(cname) = record.data {
                return Ok(cname);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No CNAME record found",
        ))
    }

    pub fn resolve_mx(&self, name: &str) -> io::Result<Vec<(u16, String)>> {
        let records = self.resolve(name, RecordType::MX)?;
        let mut mx_records = Vec::new();
        for record in records {
            if let super::record::RecordData::MX {
                preference,
                exchange,
            } = record.data
            
            {
                mx_records.push((preference, exchange));
            }
        }

        if mx_records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No MX records found",
            ));
        }

        mx_records.sort_by_key(|(pref, _)| *pref);
        Ok(mx_records)
    }

    pub fn resolve_txt(&self, name: &str) -> io::Result<Vec<Vec<String>>> {
        let records = self.resolve(name, RecordType::TXT)?;
        let mut txt_records = Vec::new();
        for record in records {
            if let super::record::RecordData::TXT(texts) = record.data {
                txt_records.push(texts);
            }
        }

        if txt_records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No TXT records found",
            ));
        }

        Ok(txt_records)
    }

    pub fn resolve_ns(&self, name: &str) -> io::Result<Vec<String>> {
        let records = self.resolve(name, RecordType::NS)?;
        let mut ns_records = Vec::new();
        for record in records {
            if let super::record::RecordData::NS(nameserver) = record.data {
                ns_records.push(nameserver);
            }
        }

        if ns_records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No NS records found",
            ));
        }

        Ok(ns_records)
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> io::Result<String> {
        let servers = self.get_servers();
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No DNS servers configured",
            ));
        }

        let mut query = self.build_query();
        for &server in &servers {
            match query.reverse_lookup(ip, server) {
                Ok(name) => return Ok(name),
                Err(_) => continue,
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Reverse lookup failed",
        ))
    }

    pub fn resolve_with_cname_follow(&self, name: &str, max_depth: usize) -> io::Result<Vec<IpAddr>> {
        let mut current_name = name.to_string();
        let mut depth = 0;
        loop {
            if depth >= max_depth {
                return Err(io::Error::new(io::ErrorKind::Other, "CNAME chain too deep"));
            }

            if let Ok(addrs) = self.resolve_host(&current_name) {
                return Ok(addrs);
            }

            match self.resolve_cname(&current_name) {
                Ok(cname) => {
                    current_name = cname;
                    depth += 1;
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "Unable to resolve host",
                    ));
                }
            }
        }
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn cache_statistics(&self) -> CacheStats {
        self.cache.get_statistics()
    }

    pub fn cleanup_cache(&self) {
        self.cache.cleanup();
    }

    pub fn export_secure_profile(&self, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let servers = self.get_servers().iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",");
        let cache_stats_blob = self.cache.export_stats_secure(algorithm)?;
        let cache_stats_b64 = pem::encode(&cache_stats_blob);
        let raw_profile = format!(
            "timeout-ms={}\nretries={}\nenable-cache={}\naccept-encoding={}\nprefer-secure-queries={}\nsecure-fallback-to-plain={}\nservers={}\ncache-stats-b64={}\n",
            self.timeout.as_millis(),
            self.retries,
            self.enable_cache,
            self.accept_encoding,
            self.prefer_secure_queries,
            self.secure_fallback_to_plain,
            servers,
            cache_stats_b64
        );

        let raw = raw_profile.into_bytes();
        let nonce = random::generate_random(16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate resolver profile nonce: {}", e),
            )
        })?;

        let encoded = match algorithm {
            CompressionAlgorithm::Identity => raw.clone(),
            _ => compression::compress(algorithm, &raw, CompressionLevel::Default)?,
        };

        let digest = compute_resolver_profile_digest(&nonce, &raw);
        let digest_b64 = pem::encode(&digest);
        let nonce_b64 = pem::encode(&nonce);
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\nraw-size={raw_size}\nencoded-size={encoded_size}\n\n",
            magic = RESOLVER_PROFILE_MAGIC,
            encoding = algorithm.content_encoding(),
            nonce = nonce_b64,
            digest = digest_b64,
            raw_size = raw.len(),
            encoded_size = encoded.len(),
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded);

        Ok(out)
    }

    pub fn import_secure_profile(data: &[u8]) -> io::Result<(SecureResolverProfileMeta, DnsResolver, Option<CacheStats>)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_profile_meta(&header, body.len())?;
        let decoded = match meta.algorithm {
            CompressionAlgorithm::Identity => body.to_vec(),
            _ => compression::decompress(meta.algorithm, body)?,
        };

        if decoded.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver profile decoded payload size mismatch",
            ));
        }

        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in resolver profile",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in resolver profile",
            )
        })?;

        let computed = compute_resolver_profile_digest(&nonce, &decoded);
        if !constant_time_eq(&computed, &expected_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver profile digest verification failed",
            ));
        }

        let payload = String::from_utf8(decoded).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver profile payload is not valid UTF-8",
            )
        })?;

        let map = parse_kv_payload(&payload);
        let timeout_ms = map.get("timeout-ms").and_then(|v| v.parse::<u64>().ok()).unwrap_or(5000);
        let retries = map.get("retries").and_then(|v| v.parse::<usize>().ok()).unwrap_or(3);
        let enable_cache = map.get("enable-cache").map(|v| parse_bool(v)).unwrap_or(true);
        let accept_encoding = map.get("accept-encoding").cloned().unwrap_or_else(|| "br, zstd, gzip, deflate, identity".to_string());
        let prefer_secure_queries = map.get("prefer-secure-queries").map(|v| parse_bool(v)).unwrap_or(false);
        let secure_fallback_to_plain = map.get("secure-fallback-to-plain").map(|v| parse_bool(v)).unwrap_or(true);
        let servers = map.get("servers").map(|raw| {
                raw.split(',').filter_map(|v| v.trim().parse::<SocketAddr>().ok()).collect::<Vec<_>>()
            }).unwrap_or_default();

        let cache_stats = if let Some(stats_b64) = map.get("cache-stats-b64") {
            if let Ok(stats_blob) = pem::decode(stats_b64) {
                DnsCache::import_stats_secure(&stats_blob).ok()
            } else {
                None
            }
        } else {
            None
        };

        let mut resolver = if servers.is_empty() {
            DnsResolver::new()
        } else {
            DnsResolver::with_servers(servers)
        };

        resolver.timeout = Duration::from_millis(timeout_ms);
        resolver.retries = retries;
        resolver.enable_cache = enable_cache;
        resolver.accept_encoding = accept_encoding;
        resolver.prefer_secure_queries = prefer_secure_queries;
        resolver.secure_fallback_to_plain = secure_fallback_to_plain;

        Ok((meta, resolver, cache_stats))
    }

    fn build_query(&self) -> DnsQuery {
        DnsQuery::new().with_timeout(self.timeout).with_accept_encoding(self.accept_encoding.clone())
            .with_secure_transport(self.prefer_secure_queries)
            .with_secure_fallback(self.secure_fallback_to_plain)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_resolver_profile_digest(nonce: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(nonce.len() + payload.len());
    material.extend_from_slice(nonce);
    material.extend_from_slice(payload);

    sha256(&material)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    if let Some(pos) = data.windows(DELIM.len()).position(|w| w == DELIM) {
        let header = String::from_utf8(data[..pos].to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver profile header is not valid UTF-8",
            )
        })?;

        let body = &data[pos + DELIM.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "resolver profile separator not found",
    ))
}

fn parse_secure_profile_meta(header: &str, body_len: usize) -> io::Result<SecureResolverProfileMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != RESOLVER_PROFILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid resolver profile magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    for line in lines {
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported resolver profile content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "resolver profile missing nonce")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "resolver profile missing digest")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "resolver profile missing raw-size")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "resolver profile missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resolver profile encoded-size does not match body length",
        ));
    }

    Ok(SecureResolverProfileMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        raw_size,
        encoded_size,
    })
}

fn parse_kv_payload(payload: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in payload.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    
    map
}

fn parse_bool(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_creation() {
        let resolver = DnsResolver::new();
        assert!(resolver.enable_cache);
        assert_eq!(resolver.retries, 3);
        assert_eq!(resolver.timeout, Duration::from_secs(5));
        assert!(!resolver.prefer_secure_queries);
        assert!(resolver.secure_fallback_to_plain);
    }

    #[test]
    fn test_resolver_with_options() {
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_secs(10))
            .with_retries(5)
            .with_cache(false)
            .with_accept_encoding("gzip, identity")
            .with_secure_queries(true)
            .with_secure_fallback(false);

        assert_eq!(resolver.timeout, Duration::from_secs(10));
        assert_eq!(resolver.retries, 5);
        assert!(!resolver.enable_cache);
        assert_eq!(resolver.accept_encoding, "gzip, identity");
        assert!(resolver.prefer_secure_queries);
        assert!(!resolver.secure_fallback_to_plain);
    }

    #[test]
    fn test_default_servers() {
        let resolver = DnsResolver::new();
        let servers = resolver.get_servers();
        assert!(!servers.is_empty());
        assert!(servers.len() >= 3);
    }

    #[test]
    fn test_add_server() {
        let resolver = DnsResolver::new();
        let custom_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);

        resolver.add_server(custom_server);
        let servers = resolver.get_servers();
        assert!(servers.contains(&custom_server));
    }

    #[test]
    fn test_set_servers() {
        let resolver = DnsResolver::new();
        let new_servers = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)];

        resolver.set_servers(new_servers.clone());
        let servers = resolver.get_servers();
        assert_eq!(servers, new_servers);
    }

    #[test]
    fn test_cache_operations() {
        let resolver = DnsResolver::new();

        let initial_stats = resolver.cache_statistics();
        assert_eq!(initial_stats.total_keys, 0);

        resolver.clear_cache();
        let stats = resolver.cache_statistics();
        assert_eq!(stats.total_keys, 0);
    }

    #[test]
    fn test_with_cache_size() {
        let resolver = DnsResolver::new().with_cache_size(500);
        assert!(resolver.enable_cache);
    }

    #[test]
    fn test_resolve_no_servers() {
        let resolver = DnsResolver::new();
        resolver.set_servers(vec![]);

        let result = resolver.resolve("example.com", RecordType::A);
        assert!(result.is_err());
    }

    #[test]
    fn test_export_import_secure_profile_identity() {
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_millis(3200))
            .with_retries(7)
            .with_cache(false)
            .with_accept_encoding("gzip, identity")
            .with_secure_queries(true)
            .with_secure_fallback(false);

        let blob = resolver
            .export_secure_profile(CompressionAlgorithm::Identity)
            .unwrap();

        let (meta, imported, maybe_stats) = DnsResolver::import_secure_profile(&blob).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(imported.timeout, Duration::from_millis(3200));
        assert_eq!(imported.retries, 7);
        assert!(!imported.enable_cache);
        assert_eq!(imported.accept_encoding, "gzip, identity");
        assert!(imported.prefer_secure_queries);
        assert!(!imported.secure_fallback_to_plain);
        assert!(maybe_stats.is_some());
    }

    #[test]
    fn test_export_import_secure_profile_gzip() {
        let resolver = DnsResolver::new().with_secure_queries(true);
        let blob = resolver
            .export_secure_profile(CompressionAlgorithm::Gzip)
            .unwrap();

        let (meta, imported, _) = DnsResolver::import_secure_profile(&blob).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);
        assert!(imported.prefer_secure_queries);
    }

    #[test]
    fn test_secure_profile_tamper_detection() {
        let resolver = DnsResolver::new();
        let mut blob = resolver
            .export_secure_profile(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = DnsResolver::import_secure_profile(&blob);
        assert!(result.is_err());
    }
}