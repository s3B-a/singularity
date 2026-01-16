use super::record::{RecordType, DnsRecord};
use std::collections::HashMap;
use std::time::Instant;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
struct CacheEntry {
    record: DnsRecord,
    insert_time: Instant,
}

impl CacheEntry {
    fn new(record: DnsRecord) -> Self {
        Self {
            record,
            insert_time: Instant::now(),
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
}

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<CacheKey, Vec<CacheEntry>>>>,
    max_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
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
        Self {
            name: name.to_lowercase(),
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

        cache.entry(key).or_insert_with(Vec::new).push(CacheEntry::new(record));
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
            let valid_records: Vec<DnsRecord> = entries.iter().filter(|entry| !entry.is_expired())
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

    pub fn cleanup_expired(&self, cache: &mut HashMap<CacheKey, Vec<CacheEntry>>) {
        cache.retain(|_, entries| {
            entries.retain(|entry| !entry.is_expired());
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
        
        let mut total_entries = 0;
        let mut expired_entries = 0;
        let mut min_ttl = u32::MAX;
        let mut max_ttl = 0u32;
        for entries in cache.values() {
            for entry in entries {
                total_entries += 1;
                if entry.is_expired() {
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
}