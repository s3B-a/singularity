use super::error::{ErrorCode, Http2Error, Result};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushStatus {
    Pending,
    Received,
    Complete,
    Rejected,
    Failed,
}

#[derive(Debug, Clone)]
pub struct PushedResource {
    pub stream_id: u32,
    pub parent_stream_id: u32,
    pub req_headers: Vec<(String, String)>,
    pub res_headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub status: PushStatus,
    pub received_at: Instant,
    pub cache_key: String,
    pub used: bool,
}

impl PushedResource {
    pub fn new(stream_id: u32, parent_stream_id: u32, req_headers: Vec<(String, String)>) -> Self {
        let cache_key = Self::build_cache_key(&req_headers);
        Self {
            stream_id,
            parent_stream_id,
            req_headers,
            res_headers: Vec::new(),
            body: Vec::new(),
            status: PushStatus::Pending,
            received_at: Instant::now(),
            cache_key,
            used: false,
        }
    }

    fn build_cache_key(header: &[(String, String)]) -> String {
        let mut method = "GET";
        let mut path = "/";
        let mut authority = "";
        let mut scheme = "https";
        for (name, value) in header {
            match name.as_str() {
                ":method" => method = value,
                ":path" => path = value,
                ":authority" => authority = value,
                ":scheme" => scheme = value,
                _ => {}
            }
        }

        format!("{}://{}{}#{}", scheme, authority, path, method)
    }

    pub fn url(&self) -> String {
        let mut path = "/";
        let mut authority = "";
        let mut scheme = "https";
        for (name, value) in &self.req_headers {
            match name.as_str() {
                ":path" => path = value,
                ":authority" => authority = value,
                ":scheme" => scheme = value,
                _ => {}
            }
        }

        format!("{}://{}{}", scheme, authority, path)
    }

    pub fn method(&self) -> String {
        self.req_headers.iter().find(|(name, _)| name == ":method")
        .map(|(_, value)| value.clone()).unwrap_or_else(|| "GET".to_string())
    }

    pub fn is_complete(&self) -> bool {
        self.status == PushStatus::Complete
    }

    pub fn is_pending(&self) -> bool {
        self.status == PushStatus::Pending
    }

    pub fn mark_complete(&mut self) {
        self.status = PushStatus::Complete;
    }

    pub fn mark_rejected(&mut self) {
        self.status = PushStatus::Rejected;
    }

    pub fn mark_failed(&mut self) {
        self.status = PushStatus::Failed;
    }

    pub fn mark_used(&mut self) {
        self.used = true;
    }

    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.received_at)
    }

    pub fn add_response_headers(&mut self, headers: Vec<(String, String)>) {
        self.res_headers.extend(headers);
        if self.status == PushStatus::Pending {
            self.status = PushStatus::Received;
        }
    }

    pub fn add_body(&mut self, data: Vec<u8>) {
        self.body.extend(data);
    }

    pub fn status_code(&self) -> Option<u16> {
        self.res_headers.iter().find(|(name, _)| name == ":status")
        .and_then(|(_, value)| value.parse().ok())
    }
}

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub enabled: bool,
    pub max_concurrent_pushes: usize,
    pub max_push_age: Duration,
    pub max_cache_size: usize,
    pub reject_content_types: HashSet<String>,
    pub same_origin_only: bool,
}

impl Default for PushConfig {
    fn default() -> Self {
        let mut reject_content_types = HashSet::new();
        reject_content_types.insert("video/".to_string());
        reject_content_types.insert("audio/".to_string());

        Self {
            enabled: true,
            max_concurrent_pushes: 10,
            max_push_age: Duration::from_secs(300),
            max_cache_size: 50,
            reject_content_types,
            same_origin_only: true,
        }
    }
}

pub struct PushManager {
    config: PushConfig,
    pushed_resources: HashMap<u32, PushedResource>,
    push_cache: HashMap<String, u32>,
    pending_promises: HashMap<u32, u32>,
    connection_origin: Option<String>,
}

impl PushManager {
    pub fn new(config: PushConfig) -> Self {
        Self {
            config,
            pushed_resources: HashMap::new(),
            push_cache: HashMap::new(),
            pending_promises: HashMap::new(),
            connection_origin: None,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(PushConfig::default())
    }

    pub fn set_origin(&mut self, origin: String) {
        self.connection_origin = Some(origin);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn concurrent_pushes(&self) -> usize {
        self.pushed_resources.values().filter(|res| res.is_pending()).count()
    }

    pub fn can_accept_push(&self) -> bool {
        self.config.enabled && self.concurrent_pushes() < self.config.max_concurrent_pushes
    }

    pub fn handle_push_promise(&mut self, parent_stream_id: u32, promised_stream_id: u32, headers: Vec<(String, String)>) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        if !self.can_accept_push() {
            eprintln!("Rejected push {}: max concurrent pushes reached", promised_stream_id);
            return Ok(false);
        }

        if self.config.same_origin_only {
            if let Some(ref origin) = self.connection_origin {
                if !self.is_same_origin(&headers, origin) {
                    eprintln!("Rejected push {}: cross-origin push not allowed", promised_stream_id);
                    return Ok(false);
                }
            }
        }

        let cache_key = PushedResource::build_cache_key(&headers);
        if self.push_cache.contains_key(&cache_key) {
            eprintln!("Rejected push {}: resource already pushed", promised_stream_id);
            return Ok(false);
        }

        let resource = PushedResource::new(promised_stream_id, parent_stream_id, headers);
        println!("Accepted push promise: stream={}, url={}", promised_stream_id, resource.url());

        self.pending_promises.insert(parent_stream_id, promised_stream_id);
        self.pushed_resources.insert(promised_stream_id, resource);
        Ok(true)
    }

    pub fn add_push_headers(&mut self, stream_id: u32, headers: Vec<(String, String)>) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| Http2Error::Protocol(
            ErrorCode::ProtocolError,
            format!("No pushed resource for stream {}", stream_id),))?;
        
        if let Some((_, content_type)) = headers.iter().find(|(name, _)| name == "content-type") {
            for reject_prefix in &self.config.reject_content_types {
                if content_type.starts_with(reject_prefix) {
                    resource.mark_rejected();
                    return Err(Http2Error::Protocol(
                        ErrorCode::RefusedStream,
                        format!("Rejected push {}: content-type {}", stream_id, content_type)
                    ));
                }
            }
        }

        resource.add_response_headers(headers);
        self.pending_promises.remove(&resource.parent_stream_id);
        
        Ok(())
    }

    pub fn add_push_data(&mut self, stream_id: u32, data: Vec<u8>) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| Http2Error::Protocol(
            ErrorCode::ProtocolError, format!("No pushed resource for stream {}", stream_id)
        ))?;
        resource.add_body(data);

        Ok(())
    }

    pub fn complete_push(&mut self, stream_id: u32) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| Http2Error::Protocol(
            ErrorCode::ProtocolError, format!("No pushed resource for stream {}", stream_id)
        ))?;

        resource.mark_complete();
        let cache_key = resource.cache_key.clone();
        self.push_cache.insert(cache_key, stream_id);
        println!("Completed push: stream={}, url={}, size={} bytes", stream_id, resource.url(), resource.body.len());

        Ok(())
    }

    pub fn reject_push(&mut self, stream_id: u32) -> Result<()> {
        if let Some(resource) = self.pushed_resources.get_mut(&stream_id) {
            resource.mark_rejected();
            self.pending_promises.remove(&stream_id);
        }

        Ok(())
    }

    pub fn get_push(&self, stream_id: u32) -> Option<&PushedResource> {
        self.pushed_resources.get(&stream_id)
    }

    pub fn get_push_mut(&mut self, stream_id: u32) -> Option<&mut PushedResource> {
        self.pushed_resources.get_mut(&stream_id)
    }

    pub fn find_cached_push(&mut self, url: &str, method: &str) -> Option<&PushedResource> {
        let cache_key = format!("{}#{}", url, method);
        if let Some(&stream_id) = self.push_cache.get(&cache_key) {
            if let Some(resource) = self.pushed_resources.get_mut(&stream_id) {
                if resource.is_complete() {
                    resource.mark_used();
                    println!("Using cached pushed resource: stream={}, url={}", stream_id, url);
                    return Some(resource);
                }
            }
        }

        None
    }

    pub fn all_pushes(&self) -> Vec<&PushedResource> {
        self.pushed_resources.values().collect()
    }

    pub fn completed_pushes(&self) -> Vec<&PushedResource> {
        self.pushed_resources.values().filter(|r| r.is_complete()).collect()
    }

    pub fn pending_pushes(&self) -> Vec<&PushedResource> {
        self.pushed_resources.values().filter(|r| r.is_pending()).collect()
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let expired: Vec<u32> = self.pushed_resources.iter().filter(|(_, res)| {
            res.is_complete() && !res.used && now.duration_since(res.received_at) > self.config.max_push_age
        }).map(|(&stream_id, _)| stream_id).collect();

        for stream_id in expired {
            if let Some(resource) = self.pushed_resources.remove(&stream_id) {
                self.push_cache.remove(&resource.cache_key);
                println!("Cleaned up expired pushed resource: stream={}, url={}", stream_id, resource.url());
            }
        }

        if self.pushed_resources.len() > self.config.max_cache_size {
            let to_remove = self.pushed_resources.len() - self.config.max_cache_size;
            let mut unused: Vec<_> = self.pushed_resources.iter().filter(|(_, res)| !res.used && res.is_complete()).map(|(&id, res)| (id, res.received_at)).collect();

            unused.sort_by_key(|&(_, time)| time);
            for (stream_id, _) in unused.iter().take(to_remove) {
                if let Some(resource) = self.pushed_resources.remove(stream_id) {
                    self.push_cache.remove(&resource.cache_key);
                }
            }
        }
    }

    fn is_same_origin(&self, headers: &[(String, String)], origin: &str) -> bool {
        let authority = headers.iter().find(|(name, _)| name == ":authority").map(|(_, value)| value);
        let scheme = headers.iter().find(|(name, _)| name == ":scheme").map(|(_, value)| value);
        if let(Some(auth), Some(sch)) = (authority, scheme) {
            let push_origin = format!("{}://{}", sch, auth);
            push_origin == origin
        } else {
            false
        }
    }

    pub fn stats(&self) -> PushStats {
        let total = self.pushed_resources.len();
        let complete = self.pushed_resources.values().filter(|r| r.is_complete()).count();
        let pending = self.pushed_resources.values().filter(|r| r.is_pending()).count();
        let used = self.pushed_resources.values().filter(|r| r.used).count();
        let rejected = self.pushed_resources.values().filter(|r| r.status == PushStatus::Rejected).count();

        PushStats {
            total,
            complete,
            pending,
            used,
            rejected,
            cache_size: self.push_cache.len(),
        }
    }

    pub fn clear(&mut self) {
        self.pushed_resources.clear();
        self.push_cache.clear();
        self.pending_promises.clear();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PushStats {
    pub total: usize,
    pub complete: usize,
    pub pending: usize,
    pub used: usize,
    pub rejected: usize,
    pub cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_manager_creation() {
        let manager = PushManager::with_defaults();
        assert!(manager.is_enabled());
        assert_eq!(manager.concurrent_pushes(), 0);
    }

    #[test]
    fn test_push_promise_handling() {
        let mut manager = PushManager::with_defaults();
        manager.set_origin("https://example.com".to_string());

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/style.css".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let result = manager.handle_push_promise(1, 2, headers);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(manager.pushed_resources.len(), 1);
    }

    #[test]
    fn test_cache_key_generation() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/file.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let key = PushedResource::build_cache_key(&headers);
        assert_eq!(key, "https://example.com/file.js#GET");
    }

    #[test]
    fn test_push_completion() {
        let mut manager = PushManager::with_defaults();
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/data.json".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        manager.handle_push_promise(1, 2, headers).unwrap();
        
        let response_headers = vec![
            (":status".to_string(), "200".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        
        manager.add_push_headers(2, response_headers).unwrap();
        manager.add_push_data(2, b"{}".to_vec()).unwrap();
        manager.complete_push(2).unwrap();

        let push = manager.get_push(2).unwrap();
        assert!(push.is_complete());
        assert_eq!(push.body, b"{}");
    }

    #[test]
    fn test_cached_push_lookup() {
        let mut manager = PushManager::with_defaults();
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/cached.css".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        manager.handle_push_promise(1, 2, headers).unwrap();
        manager.complete_push(2).unwrap();

        let found = manager.find_cached_push("https://example.com/cached.css", "GET");
        assert!(found.is_some());
        assert!(found.unwrap().used);
    }

    #[test]
    fn test_max_concurrent_pushes() {
        let mut config = PushConfig::default();
        config.max_concurrent_pushes = 2;
        let mut manager = PushManager::new(config);

        for i in 0..3 {
            let headers = vec![
                (":method".to_string(), "GET".to_string()),
                (":path".to_string(), format!("/file{}.css", i)),
                (":scheme".to_string(), "https".to_string()),
                (":authority".to_string(), "example.com".to_string()),
            ];

            let result = manager.handle_push_promise(1, 2 + i as u32, headers);
            
            if i < 2 {
                assert!(result.unwrap());
            } else {
                assert!(!result.unwrap());
            }
        }
    }

    #[test]
    fn test_push_stats() {
        let mut manager = PushManager::with_defaults();
        
        let headers1 = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/file1.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];
        manager.handle_push_promise(1, 2, headers1).unwrap();
        manager.complete_push(2).unwrap();

        let headers2 = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/file2.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];
        manager.handle_push_promise(1, 4, headers2).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.complete, 1);
        assert_eq!(stats.pending, 1);
    }
}