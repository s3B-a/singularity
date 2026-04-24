use super::error::{ErrorCode, Http2Error, Result};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{HashMap, HashSet};
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PUSH_MANAGER_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_PUSH_MANAGER_BLOB_V1";
const PUSH_MANAGER_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_PUSH_MANAGER_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePushManagerBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

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
        self.req_headers.iter().find(|(name, _)| {
            name == ":method"
        }).map(|(_, value)| {
            value.clone()
        }).unwrap_or_else(|| "GET".to_string())
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
        self.res_headers.iter().find(|(name, _)| {
            name == ":status"
        }).and_then(|(_, value)| value.parse().ok())
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
        self.pushed_resources.values().filter(|res| {
            res.is_pending()
        }).count()
    }

    pub fn can_accept_push(&self) -> bool {
        self.config.enabled && self.concurrent_pushes() < self.config.max_concurrent_pushes
    }

    pub fn handle_push_promise(&mut self, parent_stream_id: u32, promised_stream_id: u32, headers: Vec<(String, String)>) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        if !self.can_accept_push() {
            eprintln!(
                "Rejected push {}: max concurrent pushes reached",
                promised_stream_id
            );

            return Ok(false);
        }

        if self.config.same_origin_only {
            if let Some(ref origin) = self.connection_origin {
                if !self.is_same_origin(&headers, origin) {
                    eprintln!(
                        "Rejected push {}: cross-origin push not allowed",
                        promised_stream_id
                    );

                    return Ok(false);
                }
            }
        }

        let cache_key = PushedResource::build_cache_key(&headers);
        if self.push_cache.contains_key(&cache_key) {
            eprintln!(
                "Rejected push {}: resource already pushed",
                promised_stream_id
            );

            return Ok(false);
        }

        let resource = PushedResource::new(promised_stream_id, parent_stream_id, headers);
        println!(
            "Accepted push promise: stream={}, url={}",
            promised_stream_id,
            resource.url()
        );

        self.pending_promises.insert(parent_stream_id, promised_stream_id);
        self.pushed_resources.insert(promised_stream_id, resource);
        Ok(true)
    }

    pub fn add_push_headers(&mut self, stream_id: u32, headers: Vec<(String, String)>) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| {
            Http2Error::Protocol(
                ErrorCode::ProtocolError,
                format!("No pushed resource for stream {}", stream_id),
            )
        })?;

        if let Some((_, content_type)) = headers.iter().find(|(name, _)| name == "content-type") {
            for reject_prefix in &self.config.reject_content_types {
                if content_type.starts_with(reject_prefix) {
                    resource.mark_rejected();
                    return Err(Http2Error::Protocol(
                        ErrorCode::RefusedStream,
                        format!("Rejected push {}: content-type {}", stream_id, content_type),
                    ));
                }
            }
        }

        resource.add_response_headers(headers);
        self.pending_promises.remove(&resource.parent_stream_id);
        
        Ok(())
    }

    pub fn add_push_data(&mut self, stream_id: u32, data: Vec<u8>) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| {
            Http2Error::Protocol(
                ErrorCode::ProtocolError,
                format!("No pushed resource for stream {}", stream_id),
            )
        })?;

        resource.add_body(data);
        Ok(())
    }

    pub fn complete_push(&mut self, stream_id: u32) -> Result<()> {
        let resource = self.pushed_resources.get_mut(&stream_id).ok_or_else(|| {
            Http2Error::Protocol(
                ErrorCode::ProtocolError,
                format!("No pushed resource for stream {}", stream_id),
            )
        })?;

        resource.mark_complete();
        let cache_key = resource.cache_key.clone();
        self.push_cache.insert(cache_key, stream_id);
        println!(
            "Completed push: stream={}, url={}, size={} bytes",
            stream_id,
            resource.url(),
            resource.body.len()
        );

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
                    println!(
                        "Using cached pushed resource: stream={}, url={}",
                        stream_id, url
                    );

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
        self.pushed_resources.values().filter(|r| {
            r.is_complete()
        }).collect()
    }

    pub fn pending_pushes(&self) -> Vec<&PushedResource> {
        self.pushed_resources.values().filter(|r| {
            r.is_pending()
        }).collect()
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let expired: Vec<u32> = self.pushed_resources.iter().filter(|(_, res)| {
            res.is_complete()
                && !res.used
                && now.duration_since(res.received_at) > self.config.max_push_age
        }).map(|(&stream_id, _)| stream_id).collect();

        for stream_id in expired {
            if let Some(resource) = self.pushed_resources.remove(&stream_id) {
                self.push_cache.remove(&resource.cache_key);
                println!(
                    "Cleaned up expired pushed resource: stream={}, url={}",
                    stream_id,
                    resource.url()
                );
            }
        }

        if self.pushed_resources.len() > self.config.max_cache_size {
            let to_remove = self.pushed_resources.len() - self.config.max_cache_size;
            let mut unused: Vec<_> = self.pushed_resources.iter().filter(|(_, res)| {
                !res.used && res.is_complete()
            }).map(|(&id, res)| (id, res.received_at)).collect();

            unused.sort_by_key(|&(_, time)| time);
            for (stream_id, _) in unused.iter().take(to_remove) {
                if let Some(resource) = self.pushed_resources.remove(stream_id) {
                    self.push_cache.remove(&resource.cache_key);
                }
            }
        }
    }

    fn is_same_origin(&self, headers: &[(String, String)], origin: &str) -> bool {
        let authority = headers.iter().find(|(name, _)| {
            name == ":authority"
        }).map(|(_, value)| value);

        let scheme = headers.iter().find(|(name, _)| {
            name == ":scheme"
        }).map(|(_, value)| value);

        if let (Some(auth), Some(sch)) = (authority, scheme) {
            let push_origin = format!("{}://{}", sch, auth);
            push_origin == origin
        } else {
            false
        }
    }

    pub fn stats(&self) -> PushStats {
        let total = self.pushed_resources.len();
        let complete = self.pushed_resources.values().filter(|r| {
            r.is_complete()
        }).count();

        let pending = self.pushed_resources.values().filter(|r| {
            r.is_pending()
        }).count();

        let used = self.pushed_resources.values().filter(|r| {
            r.used
        }).count();

        let rejected = self.pushed_resources.values().filter(|r| {
            r.status == PushStatus::Rejected
        }).count();

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

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecurePushManagerBlobMeta, Vec<u8>)> {
        encode_secure_push_manager(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecurePushManagerBlobMeta, Vec<u8>)> {
        encode_secure_push_manager_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecurePushManagerBlobMeta, Self)> {
        decode_secure_push_manager(data)
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

pub fn select_secure_push_manager_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_push_manager(manager: &PushManager, algorithm: CompressionAlgorithm) -> io::Result<(SecurePushManagerBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_push_manager(manager)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate push manager blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_push_manager_blob_tag(
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
        magic = PUSH_MANAGER_BLOB_MAGIC,
        encoding = selected_algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
        issued_at = issued_at_unix
    );

    let mut blob = header.into_bytes();
    blob.extend_from_slice(&encoded_payload);

    Ok((
        SecurePushManagerBlobMeta {
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

pub fn encode_secure_push_manager_auto(manager: &PushManager, accept_encoding: &str) -> io::Result<(SecurePushManagerBlobMeta, Vec<u8>)> {
    let selected = select_secure_push_manager_algorithm(accept_encoding);
    encode_secure_push_manager(manager, selected)
}

pub fn decode_secure_push_manager(data: &[u8]) -> io::Result<(SecurePushManagerBlobMeta, PushManager)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_push_manager_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_push_manager_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "push manager blob HMAC mismatch",
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
                "raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "push manager blob digest mismatch",
        ));
    }

    let manager = deserialize_push_manager(&raw_payload)?;
    Ok((meta, manager))
}

fn serialize_push_manager(manager: &PushManager) -> io::Result<Vec<u8>> {
    let mut lines = Vec::new();

    lines.push(format!("config-enabled={}", manager.config.enabled));
    lines.push(format!(
        "config-max-concurrent-pushes={}",
        manager.config.max_concurrent_pushes
    ));

    lines.push(format!(
        "config-max-push-age-ms={}",
        manager.config.max_push_age.as_millis()
    ));

    lines.push(format!("config-max-cache-size={}", manager.config.max_cache_size));
    lines.push(format!(
        "config-same-origin-only={}",
        manager.config.same_origin_only
    ));

    let mut reject_content_types: Vec<String> = manager.config.reject_content_types.iter().cloned().collect();
    reject_content_types.sort_unstable();
    lines.push(format!(
        "config-reject-content-types-count={}",
        reject_content_types.len()
    ));

    lines.push(format!(
        "config-reject-content-types={}",
        encode_string_list(&reject_content_types)
    ));

    lines.push(format!(
        "connection-origin-present={}",
        manager.connection_origin.is_some()
    ));

    if let Some(origin) = &manager.connection_origin {
        lines.push(format!(
            "connection-origin-b64={}",
            pem::encode(origin.as_bytes())
        ));
    }

    let mut stream_ids: Vec<u32> = manager.pushed_resources.keys().copied().collect();
    stream_ids.sort_unstable();
    lines.push(format!("resource-count={}", stream_ids.len()));
    let now = Instant::now();
    for (idx, stream_id) in stream_ids.iter().enumerate() {
        let resource = manager.pushed_resources.get(stream_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing pushed resource in manager map",
            )
        })?;

        let age_ms = now.saturating_duration_since(resource.received_at).as_millis().min(u128::from(u64::MAX)) as u64;
        lines.push(format!("resource-{}-stream-id={}", idx, resource.stream_id));
        lines.push(format!(
            "resource-{}-parent-stream-id={}",
            idx, resource.parent_stream_id
        ));

        lines.push(format!(
            "resource-{}-req-headers={}",
            idx,
            encode_header_pairs(&resource.req_headers)
        ));

        lines.push(format!(
            "resource-{}-res-headers={}",
            idx,
            encode_header_pairs(&resource.res_headers)
        ));

        lines.push(format!(
            "resource-{}-body={}",
            idx,
            pem::encode(&resource.body)
        ));

        lines.push(format!(
            "resource-{}-status={}",
            idx,
            push_status_as_str(resource.status)
        ));

        lines.push(format!("resource-{}-age-ms={}", idx, age_ms));
        lines.push(format!(
            "resource-{}-cache-key={}",
            idx,
            pem::encode(resource.cache_key.as_bytes())
        ));

        lines.push(format!("resource-{}-used={}", idx, resource.used));
    }

    let mut cache_entries: Vec<(&String, &u32)> = manager.push_cache.iter().collect();
    cache_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    lines.push(format!("cache-count={}", cache_entries.len()));
    for (idx, (cache_key, stream_id)) in cache_entries.iter().enumerate() {
        lines.push(format!(
            "cache-{}-key={}",
            idx,
            pem::encode(cache_key.as_bytes())
        ));
        
        lines.push(format!("cache-{}-stream-id={}", idx, stream_id));
    }

    let mut pending_entries: Vec<(&u32, &u32)> = manager.pending_promises.iter().collect();
    pending_entries.sort_by_key(|(parent_id, _)| **parent_id);
    lines.push(format!("pending-count={}", pending_entries.len()));
    for (idx, (parent_id, promised_id)) in pending_entries.iter().enumerate() {
        lines.push(format!("pending-{}-parent-id={}", idx, parent_id));
        lines.push(format!("pending-{}-promised-id={}", idx, promised_id));
    }

    Ok(lines.join("\n").into_bytes())
}

fn deserialize_push_manager(raw_payload: &[u8]) -> io::Result<PushManager> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "push manager payload is not valid UTF-8",
        )
    })?;

    let mut kv = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid push manager payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let enabled = parse_bool(required_field(&kv, "config-enabled")?, "config-enabled")?;
    let max_concurrent_pushes = parse_usize(
        required_field(&kv, "config-max-concurrent-pushes")?,
        "config-max-concurrent-pushes",
    )?;

    let max_push_age_ms = parse_u64(
        required_field(&kv, "config-max-push-age-ms")?,
        "config-max-push-age-ms",
    )?;

    let max_cache_size = parse_usize(
        required_field(&kv, "config-max-cache-size")?,
        "config-max-cache-size",
    )?;

    let same_origin_only = parse_bool(
        required_field(&kv, "config-same-origin-only")?,
        "config-same-origin-only",
    )?;

    let _reject_count = parse_usize(
        required_field(&kv, "config-reject-content-types-count")?,
        "config-reject-content-types-count",
    )?;

    let reject_content_types: HashSet<String> = decode_string_list(
        required_field(&kv, "config-reject-content-types")?,
        "config-reject-content-types",
    )?.into_iter().collect();

    let config = PushConfig {
        enabled,
        max_concurrent_pushes,
        max_push_age: Duration::from_millis(max_push_age_ms),
        max_cache_size,
        reject_content_types,
        same_origin_only,
    };

    let connection_origin_present = parse_bool(
        required_field(&kv, "connection-origin-present")?,
        "connection-origin-present",
    )?;

    let connection_origin = if connection_origin_present {
        let encoded = required_field(&kv, "connection-origin-b64")?;
        let raw = pem::decode(encoded).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid connection origin encoding: {}", e),
            )
        })?;

        Some(String::from_utf8(raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "connection origin is not valid UTF-8",
            )
        })?)
    } else {
        None
    };

    let resource_count = parse_usize(required_field(&kv, "resource-count")?, "resource-count")?;
    let now = Instant::now();
    let mut pushed_resources = HashMap::new();
    for idx in 0..resource_count {
        let stream_id = parse_u32(
            required_field(&kv, &format!("resource-{}-stream-id", idx))?,
            &format!("resource-{}-stream-id", idx),
        )?;

        let parent_stream_id = parse_u32(
            required_field(&kv, &format!("resource-{}-parent-stream-id", idx))?,
            &format!("resource-{}-parent-stream-id", idx),
        )?;

        let req_headers = decode_header_pairs(
            required_field(&kv, &format!("resource-{}-req-headers", idx))?,
            &format!("resource-{}-req-headers", idx),
        )?;

        let res_headers = decode_header_pairs(
            required_field(&kv, &format!("resource-{}-res-headers", idx))?,
            &format!("resource-{}-res-headers", idx),
        )?;

        let body = pem::decode(required_field(&kv, &format!("resource-{}-body", idx))?).map_err(
            |e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid resource-{}-body encoding: {}", idx, e),
                )
            },
        )?;

        let status = parse_push_status(required_field(
            &kv,
            &format!("resource-{}-status", idx),
        )?)?;

        let age_ms = parse_u64(
            required_field(&kv, &format!("resource-{}-age-ms", idx))?,
            &format!("resource-{}-age-ms", idx),
        )?;

        let cache_key = {
            let raw = pem::decode(required_field(
                &kv,
                &format!("resource-{}-cache-key", idx),
            )?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid resource-{}-cache-key encoding: {}", idx, e),
                )
            })?;

            String::from_utf8(raw).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("resource-{}-cache-key is not valid UTF-8", idx),
                )
            })?
        };

        let used = parse_bool(
            required_field(&kv, &format!("resource-{}-used", idx))?,
            &format!("resource-{}-used", idx),
        )?;

        let received_at = now.checked_sub(Duration::from_millis(age_ms)).unwrap_or(now);
        let resource = PushedResource {
            stream_id,
            parent_stream_id,
            req_headers,
            res_headers,
            body,
            status,
            received_at,
            cache_key,
            used,
        };

        if pushed_resources.insert(stream_id, resource).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate stream id '{}' in pushed resources", stream_id),
            ));
        }
    }

    let cache_count = parse_usize(required_field(&kv, "cache-count")?, "cache-count")?;
    let mut push_cache = HashMap::new();
    for idx in 0..cache_count {
        let cache_key_raw =
            pem::decode(required_field(&kv, &format!("cache-{}-key", idx))?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid cache-{}-key encoding: {}", idx, e),
                )
            })?;

        let cache_key = String::from_utf8(cache_key_raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cache-{}-key is not valid UTF-8", idx),
            )
        })?;

        let stream_id = parse_u32(
            required_field(&kv, &format!("cache-{}-stream-id", idx))?,
            &format!("cache-{}-stream-id", idx),
        )?;

        if !pushed_resources.contains_key(&stream_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cache-{} references unknown pushed resource stream {}",
                    idx, stream_id
                ),
            ));
        }

        push_cache.insert(cache_key, stream_id);
    }

    let pending_count = parse_usize(required_field(&kv, "pending-count")?, "pending-count")?;
    let mut pending_promises = HashMap::new();
    for idx in 0..pending_count {
        let parent_id = parse_u32(
            required_field(&kv, &format!("pending-{}-parent-id", idx))?,
            &format!("pending-{}-parent-id", idx),
        )?;

        let promised_id = parse_u32(
            required_field(&kv, &format!("pending-{}-promised-id", idx))?,
            &format!("pending-{}-promised-id", idx),
        )?;

        if !pushed_resources.contains_key(&promised_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "pending-{} references unknown promised stream {}",
                    idx, promised_id
                ),
            ));
        }

        pending_promises.insert(parent_id, promised_id);
    }

    Ok(PushManager {
        config,
        pushed_resources,
        push_cache,
        pending_promises,
        connection_origin,
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing '{}' in push manager payload", key),
        )
    })
}

fn parse_bool(v: &str, field: &str) -> io::Result<bool> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} '{}'", field, v),
        )),
    }
}

fn parse_u32(v: &str, field: &str) -> io::Result<u32> {
    v.parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} '{}'", field, v),
        )
    })
}

fn parse_u64(v: &str, field: &str) -> io::Result<u64> {
    v.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} '{}'", field, v),
        )
    })
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} '{}'", field, v),
        )
    })
}

fn push_status_as_str(status: PushStatus) -> &'static str {
    match status {
        PushStatus::Pending => "pending",
        PushStatus::Received => "received",
        PushStatus::Complete => "complete",
        PushStatus::Rejected => "rejected",
        PushStatus::Failed => "failed",
    }
}

fn parse_push_status(v: &str) -> io::Result<PushStatus> {
    match v {
        "pending" => Ok(PushStatus::Pending),
        "received" => Ok(PushStatus::Received),
        "complete" => Ok(PushStatus::Complete),
        "rejected" => Ok(PushStatus::Rejected),
        "failed" => Ok(PushStatus::Failed),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid push status '{}'", v),
        )),
    }
}

fn encode_string_list(values: &[String]) -> String {
    let payload = values.iter().map(|v| {
        pem::encode(v.as_bytes())
    }).collect::<Vec<_>>().join("\n");

    pem::encode(payload.as_bytes())
}

fn decode_string_list(encoded: &str, field: &str) -> io::Result<Vec<String>> {
    let raw = pem::decode(encoded).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })?;

    let text = String::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", field),
        )
    })?;

    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    text.lines().map(|line| {
        let bytes = pem::decode(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} entry encoding: {}", field, e),
            )
        })?;

        String::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} entry is not valid UTF-8", field),
            )
        })
    }).collect()
}

fn encode_header_pairs(headers: &[(String, String)]) -> String {
    let mut lines = Vec::new();
    for (name, value) in headers {
        lines.push(format!(
            "{}={}",
            pem::encode(name.as_bytes()),
            pem::encode(value.as_bytes())
        ));
    }

    pem::encode(lines.join("\n").as_bytes())
}

fn decode_header_pairs(encoded: &str, field: &str) -> io::Result<Vec<(String, String)>> {
    let raw = pem::decode(encoded).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })?;

    let text = String::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", field),
        )
    })?;

    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut headers = Vec::new();
    for line in text.lines() {
        let (name_b64, value_b64) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} line '{}'", field, line),
            )
        })?;

        let name_raw = pem::decode(name_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} name encoding: {}", field, e),
            )
        })?;

        let value_raw = pem::decode(value_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} value encoding: {}", field, e),
            )
        })?;

        let name = String::from_utf8(name_raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} name is not valid UTF-8", field),
            )
        })?;

        let value = String::from_utf8(value_raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} value is not valid UTF-8", field),
            )
        })?;

        headers.push((name, value));
    }

    Ok(headers)
}

fn compute_push_manager_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(PUSH_MANAGER_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(PUSH_MANAGER_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing blob header/body separator",
    ))
}

fn parse_secure_push_manager_meta(header: &str, body_len: usize) -> io::Result<SecurePushManagerBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != PUSH_MANAGER_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure push manager blob magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure push manager header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm =
                    CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    })?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure push manager blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure push manager blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure push manager blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure push manager blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure push manager blob",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded-size mismatch: metadata {}, actual {}",
                encoded_size, body_len
            ),
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in secure push manager blob",
        )
    })?;

    Ok(SecurePushManagerBlobMeta {
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

    #[test]
    fn test_secure_push_manager_roundtrip_identity() {
        let mut manager = PushManager::with_defaults();
        manager.set_origin("https://example.com".to_string());

        let headers1 = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/main.css".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        manager.handle_push_promise(1, 2, headers1).unwrap();
        manager
            .add_push_headers(
                2,
                vec![
                    (":status".to_string(), "200".to_string()),
                    ("content-type".to_string(), "text/css".to_string()),
                ],
            )
            .unwrap();

        manager.add_push_data(2, b"body{}".to_vec()).unwrap();
        manager.complete_push(2).unwrap();

        let headers2 = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/app.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        manager.handle_push_promise(1, 4, headers2).unwrap();
        manager.reject_push(4).unwrap();

        let (_meta, blob) =
            encode_secure_push_manager(&manager, CompressionAlgorithm::Identity).unwrap();

        let (_decoded_meta, decoded) = decode_secure_push_manager(&blob).unwrap();
        let original_stats = manager.stats();
        let decoded_stats = decoded.stats();

        assert_eq!(decoded_stats.total, original_stats.total);
        assert_eq!(decoded_stats.complete, original_stats.complete);
        assert_eq!(decoded_stats.pending, original_stats.pending);
        assert_eq!(decoded_stats.rejected, original_stats.rejected);
        assert_eq!(decoded.connection_origin, manager.connection_origin);

        let decoded_push = decoded.get_push(2).unwrap();
        assert!(decoded_push.is_complete());
        assert_eq!(decoded_push.status_code(), Some(200));
        assert_eq!(decoded_push.body, b"body{}");
    }

    #[test]
    fn test_secure_push_manager_tamper_detected() {
        let mut manager = PushManager::with_defaults();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/tamper.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        manager.handle_push_promise(1, 2, headers).unwrap();

        let (_meta, mut blob) =
            encode_secure_push_manager(&manager, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_push_manager(&blob).is_err());
    }
}