use super::cache::DnsCache;
use super::query::DnsQuery;
use super::record::{RecordType, DnsRecord};
use super::response::DnsResponse;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub struct DnsResolver {
    cache: DnsCache,
    servers: Arc<RwLock<Vec<SocketAddr>>>,
    pub timeout: Duration,
    pub retries: usize,
    pub enable_cache: bool,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            cache: DnsCache::new(1024),
            servers: Arc::new(RwLock::new(Self::default_servers())),
            timeout: Duration::from_secs(5),
            retries: 3,
            enable_cache: true,
        }
    }

    fn default_servers() -> Vec<SocketAddr> {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(84, 200, 69, 80)), 53),    // DNS.WATCH
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(84, 200, 70, 40)), 53),    // DNS.WATCH
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(91, 239, 100, 100)), 53),  // UncensoredDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(89, 233, 43, 71)), 53),    // UncensoredDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),         // Quad9
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53), // Quad9
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(193, 138, 219, 74)), 53),  // MullvadDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(193, 138, 218, 74)), 53),  // MullvadDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)), 53),    // AdGuardDNS
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)), 53),    // AdGuardDNS
        ]
    }

    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            cache: DnsCache::new(1024),
            servers: Arc::new(RwLock::new(servers)),
            timeout: Duration::from_secs(5),
            retries: 3,
            enable_cache: true,
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

        let mut query = DnsQuery::new().with_timeout(self.timeout);
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
            if let super::record::RecordData::MX { preference, exchange } = record.data {
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

        let mut query = DnsQuery::new().with_timeout(self.timeout);
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

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn cache_statistics(&self) -> super::cache::CacheStats {
        self.cache.get_statistics()
    }

    pub fn cleanup_cache(&self) {
        self.cache.cleanup();
    }

    pub fn resolve_with_cname_follow(&self, name: &str, max_depth: usize) -> io::Result<Vec<IpAddr>> {
        let mut current_name = name.to_string();
        let mut depth = 0;
        loop {
            if depth >= max_depth {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "CNAME chain too deep",
                ));
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
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
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
    }

    #[test]
    fn test_resolver_with_options() {
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_secs(10))
            .with_retries(5)
            .with_cache(false);

        assert_eq!(resolver.timeout, Duration::from_secs(10));
        assert_eq!(resolver.retries, 5);
        assert!(!resolver.enable_cache);
    }

    #[test]
    fn test_default_servers() {
        let resolver = DnsResolver::new();
        let servers = resolver.get_servers();
        assert!(!servers.is_empty());
        assert_eq!(servers.len(), 3);
    }

    #[test]
    fn test_add_server() {
        let resolver = DnsResolver::new();
        let custom_server = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            53,
        );

        resolver.add_server(custom_server);
        let servers = resolver.get_servers();
        assert!(servers.contains(&custom_server));
    }

    #[test]
    fn test_set_servers() {
        let resolver = DnsResolver::new();
        let new_servers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        ];

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
}