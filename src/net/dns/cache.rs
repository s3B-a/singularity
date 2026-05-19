use super::record::{DnsRecord, RecordType};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Instant;

const CACHE_STATS_MAGIC: &str = "SINGULARITY_DNS_CACHE_STATS_V1";

#[derive(Clone)]
struct CacheEntry {
    record: DnsRecord,
    insert_time: Instant,
    integrity_nonce: Vec<u8>,
    integrity_tag: String,
}

impl CacheEntry {
    fn new(record: DnsRecord, key_hash: &str) -> Self {
        let nonce = random::generate_random(16).unwrap_or_else(|_| vec![0u8; 16]);
        let integrity_tag = Self::compute_integrity_tag(key_hash, &record, &nonce);

        Self {
            record,
            insert_time: Instant::now(),
            integrity_nonce: nonce,
            integrity_tag,
        }
    }

    fn is_expired(&self) -> bool {
        let elapsed = self.insert_time.elapsed().as_secs() as u32;
        self.record.is_expired(elapsed)
    }

    fn remaining_ttl(&self) -> u32 {
        let elapsed = self.insert_time.elapsed().as_secs() as u32;
        self.record.ttl.saturating_sub(elapsed)
    }

    fn verify_integrity(&self, key_hash: &str) -> bool {
        let expected = Self::compute_integrity_tag(key_hash, &self.record, &self.integrity_nonce);
        constant_time_eq(expected.as_bytes(), self.integrity_tag.as_bytes())
    }

    fn compute_integrity_tag(key_hash: &str, record: &DnsRecord, nonce: &[u8]) -> String {
        let mut material = Vec::new();
        material.extend_from_slice(key_hash.as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(record.name.to_lowercase().as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(record.record_type.to_u16().to_string().as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(record.record_class.to_u16().to_string().as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(record.ttl.to_string().as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(format!("{}", record.data).as_bytes());
        material.extend_from_slice(b"|");
        material.extend_from_slice(nonce);

        pem::encode(&sha256(&material))
    }
}

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<CacheKey, Vec<CacheEntry>>>>,
    max_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name_hash: String,
    record_type: RecordType,
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_keys: usize,
    pub total_entries: usize,
    pub expired_entries: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
}

impl CacheKey {
    fn new(name: String, record_type: RecordType) -> Self {
        let normalized = name.to_lowercase();
        let name_hash = pem::encode(&sha256(normalized.as_bytes()));
        Self {
            name_hash,
            record_type,
        }
    }
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }

    pub fn insert(&self, name: &str, record: DnsRecord) {
        let key = CacheKey::new(name.to_string(), record.record_type);
        let mut cache = self.cache.write().unwrap();
        if cache.len() >= self.max_size {
            self.cleanup_expired(&mut cache);
        }

        if cache.len() >= self.max_size {
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.entry(key.clone()).or_insert_with(Vec::new).push(CacheEntry::new(record, &key.name_hash));
    }

    pub fn insert_many(&self, name: &str, records: Vec<DnsRecord>) {
        for record in records {
            self.insert(name, record);
        }
    }

    pub fn get(&self, name: &str, record_type: RecordType) -> Option<Vec<DnsRecord>> {
        let key = CacheKey::new(name.to_string(), record_type);
        let cache = self.cache.read().unwrap();
        if let Some(entries) = cache.get(&key) {
            let valid_records: Vec<DnsRecord> = entries.iter().filter(|entry| entry.verify_integrity(&key.name_hash))
                .filter(|entry| !entry.is_expired())
                .map(|entry| {
                    let mut record = entry.record.clone();
                    record.ttl = entry.remaining_ttl();
                    record
                }).collect();

            if !valid_records.is_empty() {
                return Some(valid_records);
            }
        }

        None
    }

    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    pub fn remove(&self, name: &str, record_type: RecordType) {
        let key = CacheKey::new(name.to_string(), record_type);
        let mut cache = self.cache.write().unwrap();
        cache.remove(&key);
    }

    fn cleanup_expired(&self, cache: &mut HashMap<CacheKey, Vec<CacheEntry>>) {
        cache.retain(|key, entries| {
            entries.retain(|entry| entry.verify_integrity(&key.name_hash) && !entry.is_expired());
            !entries.is_empty()
        });
    }

    pub fn cleanup(&self) {
        let mut cache = self.cache.write().unwrap();
        self.cleanup_expired(&mut cache);
    }

    pub fn size(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    pub fn contains(&self, name: &str, record_type: RecordType) -> bool {
        self.get(name, record_type).is_some()
    }

    pub fn get_statistics(&self) -> CacheStats {
        let cache = self.cache.read().unwrap();
        let mut total_entries = 0usize;
        let mut expired_entries = 0usize;
        let mut min_ttl = u32::MAX;
        let mut max_ttl = 0u32;
        for (key, entries) in cache.iter() {
            for entry in entries {
                total_entries += 1;
                if !entry.verify_integrity(&key.name_hash) || entry.is_expired() {
                    expired_entries += 1;
                } else {
                    let ttl = entry.remaining_ttl();
                    min_ttl = min_ttl.min(ttl);
                    max_ttl = max_ttl.max(ttl);
                }
            }
        }

        CacheStats {
            total_keys: cache.len(),
            total_entries,
            expired_entries,
            min_ttl: if min_ttl == u32::MAX { 0 } else { min_ttl },
            max_ttl,
        }
    }

    pub fn export_stats_secure(&self, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let stats = self.get_statistics();
        let body = format!(
            "total_keys={}\ntotal_entries={}\nexpired_entries={}\nmin_ttl={}\nmax_ttl={}\n",
            stats.total_keys, stats.total_entries, stats.expired_entries, stats.min_ttl, stats.max_ttl
        );

        let raw = body.into_bytes();
        let compressed = match algorithm {
            CompressionAlgorithm::Identity => raw.clone(),
            _ => compression::compress(algorithm, &raw, CompressionLevel::Default)?,
        };

        let digest = pem::encode(&sha256(&raw));
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\ndigest=SHA-256={digest}\nraw-size={raw_size}\nencoded-size={encoded_size}\n\n",
            magic = CACHE_STATS_MAGIC,
            encoding = algorithm.content_encoding(),
            digest = digest,
            raw_size = raw.len(),
            encoded_size = compressed.len(),
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&compressed);
        
        Ok(blob)
    }

    pub fn import_stats_secure(data: &[u8]) -> io::Result<CacheStats> {
        let (header, body) = split_header_body(data)?;
        let mut algorithm = CompressionAlgorithm::Identity;
        let mut digest_b64 = None::<String>;
        let mut raw_size = None::<usize>;
        let mut encoded_size = None::<usize>;
        let mut lines = header.lines();
        let magic = lines.next().unwrap_or_default();
        if magic != CACHE_STATS_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid secure cache stats magic",
            ));
        }

        for line in lines {
            if let Some(v) = line.strip_prefix("content-encoding=") {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unsupported content-encoding")
                })?;
            } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
                digest_b64 = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("raw-size=") {
                raw_size = v.trim().parse::<usize>().ok();
            } else if let Some(v) = line.strip_prefix("encoded-size=") {
                encoded_size = v.trim().parse::<usize>().ok();
            }
        }

        let digest_b64 = digest_b64.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure cache stats blob")
        })?;

        let raw_size = raw_size.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure cache stats blob")
        })?;

        let encoded_size = encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure cache stats blob",
            )
        })?;

        if encoded_size != body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded-size mismatch in secure cache stats blob",
            ));
        }

        let decoded = match algorithm {
            CompressionAlgorithm::Identity => body.to_vec(),
            _ => compression::decompress(algorithm, body)?,
        };

        if decoded.len() != raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "raw-size mismatch in secure cache stats blob",
            ));
        }

        let computed = pem::encode(&sha256(&decoded));
        if !constant_time_eq(computed.as_bytes(), digest_b64.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "digest verification failed for secure cache stats blob",
            ));
        }

        parse_stats_from_text(&String::from_utf8(decoded).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "secure cache stats payload is not valid UTF-8",
            )
        })?)
    }
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const SEP: &[u8] = b"\n\n";
    if let Some(pos) = data.windows(SEP.len()).position(|w| w == SEP) {
        let header = String::from_utf8(data[..pos].to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "header of secure cache stats blob is not UTF-8",
            )
        })?;

        let body = &data[pos + SEP.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "secure cache stats header/body separator missing",
    ))
}

fn parse_stats_from_text(payload: &str) -> io::Result<CacheStats> {
    let mut total_keys = None::<usize>;
    let mut total_entries = None::<usize>;
    let mut expired_entries = None::<usize>;
    let mut min_ttl = None::<u32>;
    let mut max_ttl = None::<u32>;
    for line in payload.lines() {
        if let Some(v) = line.strip_prefix("total_keys=") {
            total_keys = v.parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("total_entries=") {
            total_entries = v.parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("expired_entries=") {
            expired_entries = v.parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("min_ttl=") {
            min_ttl = v.parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("max_ttl=") {
            max_ttl = v.parse::<u32>().ok();
        }
    }

    Ok(CacheStats {
        total_keys: total_keys.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing total_keys in stats payload")
        })?,

        total_entries: total_entries.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing total_entries in stats payload")
        })?,

        expired_entries: expired_entries.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing expired_entries in stats payload",
            )
        })?,

        min_ttl: min_ttl.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing min_ttl in stats payload")
        })?,
        
        max_ttl: max_ttl.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing max_ttl in stats payload")
        })?,
    })
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        cache.insert("example.com", record.clone());

        let results = cache.get("example.com", RecordType::A);
        assert!(results.is_some());
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "Example.COM".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        cache.insert("Example.COM", record);

        let results = cache.get("example.com", RecordType::A);
        assert!(results.is_some());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "example.com".to_string(),
            1,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        cache.insert("example.com", record);

        assert!(cache.get("example.com", RecordType::A).is_some());

        thread::sleep(std::time::Duration::from_secs(2));

        assert!(cache.get("example.com", RecordType::A).is_none());
    }

    #[test]
    fn test_cache_multiple_records() {
        let cache = DnsCache::new(100);

        let record1 = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        let record2 = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 35),
        );

        cache.insert("example.com", record1);
        cache.insert("example.com", record2);

        let results = cache.get("example.com", RecordType::A);
        assert!(results.is_some());
        assert_eq!(results.unwrap().len(), 2);
    }

    #[test]
    fn test_cache_max_size() {
        let cache = DnsCache::new(5);
        for i in 0..10 {
            let record = DnsRecord::a(
                format!("example{}.com", i),
                300,
                Ipv4Addr::new(93, 184, 216, i as u8),
            );
            cache.insert(&format!("example{}.com", i), record);
        }

        assert!(cache.size() <= 5);
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        cache.insert("example.com", record);
        assert!(cache.get("example.com", RecordType::A).is_some());

        cache.clear();
        assert!(cache.get("example.com", RecordType::A).is_none());
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_cache_statistics() {
        let cache = DnsCache::new(100);

        let record1 = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        let record2 = DnsRecord::a(
            "test.com".to_string(),
            600,
            Ipv4Addr::new(93, 184, 216, 35),
        );

        cache.insert("example.com", record1);
        cache.insert("test.com", record2);

        let stats = cache.get_statistics();
        assert_eq!(stats.total_keys, 2);
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 0);
    }

    #[test]
    fn test_cache_contains() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        assert!(!cache.contains("example.com", RecordType::A));

        cache.insert("example.com", record);
        assert!(cache.contains("example.com", RecordType::A));
    }

    #[test]
    fn test_secure_stats_roundtrip_identity() {
        let cache = DnsCache::new(100);
        cache.insert(
            "example.com",
            DnsRecord::a("example.com".to_string(), 300, Ipv4Addr::new(1, 1, 1, 1)),
        );

        let blob = cache.export_stats_secure(CompressionAlgorithm::Identity).unwrap();
        let parsed = DnsCache::import_stats_secure(&blob).unwrap();
        assert_eq!(parsed.total_keys, 1);
        assert_eq!(parsed.total_entries, 1);
        assert_eq!(parsed.expired_entries, 0);
    }

    #[test]
    fn test_secure_stats_roundtrip_gzip() {
        let cache = DnsCache::new(100);
        cache.insert(
            "example.com",
            DnsRecord::a("example.com".to_string(), 300, Ipv4Addr::new(8, 8, 8, 8)),
        );

        let blob = cache.export_stats_secure(CompressionAlgorithm::Gzip).unwrap();
        let parsed = DnsCache::import_stats_secure(&blob).unwrap();

        assert_eq!(parsed.total_keys, 1);
        assert_eq!(parsed.total_entries, 1);
    }

    #[test]
    fn test_secure_stats_tamper_detection() {
        let cache = DnsCache::new(100);
        let mut blob = cache
            .export_stats_secure(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        assert!(DnsCache::import_stats_secure(&blob).is_err());
    }
}