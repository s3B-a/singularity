use super::priority::Priority;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const PRIORITY_SCHEDULER_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_PRIORITY_SCHEDULER_BLOB_V1";
const PRIORITY_SCHEDULER_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_PRIORITY_SCHEDULER_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePrioritySchedulerBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamScheduleState {
    Ready,
    Blocked,
    Idle,
    Closed,
}

#[derive(Debug, Clone)]
struct ScheduleStream {
    stream_id: u32,
    state: StreamScheduleState,
    priority: Priority,
    pending_bytes: usize,
    quantum: usize, // Weighted fair queuing ( calculated from weight )
    deficit: i64,
}

impl ScheduleStream {
    fn new(stream_id: u32, priority: Priority) -> Self {
        let quantum = Self::calculate_quantum(priority.weight);
        Self {
            stream_id,
            state: StreamScheduleState::Idle,
            priority,
            pending_bytes: 0,
            quantum,
            deficit: 0,
        }
    }

    fn calculate_quantum(weight: u8) -> usize {
        let base = 16384;
        ((base * weight as usize) / 256).max(64)
    }

    fn update_quantum(&mut self) {
        self.quantum = Self::calculate_quantum(self.priority.weight);
    }
}

#[derive(Debug, Clone)]
struct DependencyNode {
    stream_id: u32,
    parent_id: u32,
    children: Vec<u32>,
    exclusive: bool,
}

impl DependencyNode {
    fn new(stream_id: u32, parent_id: u32, exclusive: bool) -> Self {
        Self {
            stream_id,
            parent_id,
            children: Vec::new(),
            exclusive,
        }
    }
}

pub struct PriorityScheduler {
    streams: HashMap<u32, ScheduleStream>,
    dependencies: HashMap<u32, DependencyNode>,
    root_stream_id: u32,
    active_queue: VecDeque<u32>,
    blocked_streams: Vec<u32>,
    total_pending: usize,
}

impl PriorityScheduler {
    pub fn new() -> Self {
        let root_stream_id = 0;
        let mut dependencies = HashMap::new();
        dependencies.insert(
            root_stream_id,
            DependencyNode::new(root_stream_id, root_stream_id, false),
        );

        Self {
            streams: HashMap::new(),
            dependencies,
            root_stream_id,
            active_queue: VecDeque::new(),
            blocked_streams: Vec::new(),
            total_pending: 0,
        }
    }

    pub fn add_stream(&mut self, stream_id: u32, priority: Priority) {
        let parent_id = priority.stream_dependency;
        let exclusive = priority.exclusive;
        let stream = ScheduleStream::new(stream_id, priority);
        self.streams.insert(stream_id, stream);

        self.add_dependency(stream_id, parent_id, exclusive);
    }

    fn add_dependency(&mut self, stream_id: u32, parent_id: u32, exclusive: bool) {
        if parent_id != self.root_stream_id && !self.dependencies.contains_key(&parent_id) {
            self.add_dependency(stream_id, self.root_stream_id, false);
            return;
        }

        if exclusive {
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                let old_children = parent_node.children.clone();
                parent_node.children.clear();
                parent_node.children.push(stream_id);
                
                let mut new_node = DependencyNode::new(stream_id, parent_id, true);
                new_node.children = old_children.clone();
                self.dependencies.insert(stream_id, new_node);
                for child_id in &old_children {
                    if let Some(child_node) = self.dependencies.get_mut(child_id) {
                        child_node.parent_id = stream_id;
                    }
                }
            }
        } else {
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                parent_node.children.push(stream_id);
            }
            
            let new_node = DependencyNode::new(stream_id, parent_id, false);
            self.dependencies.insert(stream_id, new_node);
        }
    }

    pub fn remove_stream(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.remove(&stream_id) {
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
        }
        
        self.remove_dependency(stream_id);
        
        self.active_queue.retain(|&id| id != stream_id);
        self.blocked_streams.retain(|&id| id != stream_id);
    }

    pub fn update_priority(&mut self, stream_id: u32, priority: Priority) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let old_parent = stream.priority.stream_dependency;
            let new_parent = priority.stream_dependency;
            let exclusive = priority.exclusive;
            
            stream.priority = priority;
            stream.update_quantum();
            if old_parent != new_parent {
                self.remove_dependency(stream_id);
                self.add_dependency(stream_id, new_parent, exclusive);
            }
        }
    }

    pub fn mark_ready(&mut self, stream_id: u32, pending_bytes: usize) {
        let should_insert = if let Some(stream) = self.streams.get_mut(&stream_id) {
            let needs_insert = stream.state != StreamScheduleState::Ready;
            if needs_insert {
                stream.state = StreamScheduleState::Ready;
            }
            
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
            stream.pending_bytes = pending_bytes;
            self.total_pending += pending_bytes;
            needs_insert
        } else {
            false
        };
        
        if should_insert {
            self.blocked_streams.retain(|&id| id != stream_id);
            self.insert_into_active_queue(stream_id);
        }
    }

    pub fn mark_blocked(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.state == StreamScheduleState::Ready {
                stream.state = StreamScheduleState::Blocked;
                self.active_queue.retain(|&id| id != stream_id);
                if !self.blocked_streams.contains(&stream_id) {
                    self.blocked_streams.push(stream_id);
                }
            }
        }
    }

    pub fn mark_closed(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamScheduleState::Closed;
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
            stream.pending_bytes = 0;
        }
        
        self.active_queue.retain(|&id| id != stream_id);
        self.blocked_streams.retain(|&id| id != stream_id);
    }

    pub fn schedule_next(&mut self) -> Option<u32> {
        if self.active_queue.is_empty() {
            return None;
        }

        self.schedule_from_tree(self.root_stream_id)
    }

    fn schedule_from_tree(&mut self, parent_id: u32) -> Option<u32> {
        let children = if let Some(node) = self.dependencies.get(&parent_id) {
            node.children.clone()
        } else {
            return None;
        };

        if children.is_empty() {
            return None;
        }

        let mut weighted_children: Vec<(u32, usize, i64)> = Vec::new();
        for &child_id in &children {
            if let Some(stream) = self.streams.get(&child_id) {
                if stream.state == StreamScheduleState::Ready && stream.pending_bytes > 0 {
                    weighted_children.push((child_id, stream.quantum, stream.deficit));
                }
            }
        }

        if weighted_children.is_empty() {
            for &child_id in &children {
                if let Some(scheduled) = self.schedule_from_tree(child_id) {
                    return Some(scheduled);
                }
            }
            return None;
        }

        weighted_children.sort_by(|a, b| b.2.cmp(&a.2));
        let (selected_id, quantum, _) = weighted_children[0];
        if let Some(stream) = self.streams.get_mut(&selected_id) {
            stream.deficit -= quantum as i64;
        }

        for &child_id in &children {
            if let Some(stream) = self.streams.get_mut(&child_id) {
                if stream.state == StreamScheduleState::Ready {
                    stream.deficit += stream.quantum as i64;
                }
            }
        }

        Some(selected_id)
    }

    pub fn bytes_sent(&mut self, stream_id: u32, bytes: usize) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.pending_bytes = stream.pending_bytes.saturating_sub(bytes);
            self.total_pending = self.total_pending.saturating_sub(bytes);
            if stream.pending_bytes == 0 {
                stream.state = StreamScheduleState::Blocked;
                self.active_queue.retain(|&id| id != stream_id);
                if !self.blocked_streams.contains(&stream_id) {
                    self.blocked_streams.push(stream_id);
                }
            }
        }
    }

    pub fn get_state(&self, stream_id: u32) -> Option<StreamScheduleState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    pub fn get_priority(&self, stream_id: u32) -> Option<Priority> {
        self.streams.get(&stream_id).map(|s| s.priority.clone())
    }

    pub fn active_count(&self) -> usize {
        self.active_queue.len()
    }

    pub fn total_pending_bytes(&self) -> usize {
        self.total_pending
    }

    pub fn has_ready_streams(&self) -> bool {
        !self.active_queue.is_empty()
    }

    fn remove_dependency(&mut self, stream_id: u32) {
        if let Some(node) = self.dependencies.remove(&stream_id) {
            let parent_id = node.parent_id;
            let children = node.children;
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                parent_node.children.retain(|&id| id != stream_id);
                parent_node.children.extend(children.iter());
            }
            
            for &child_id in &children {
                if let Some(child_node) = self.dependencies.get_mut(&child_id) {
                    child_node.parent_id = parent_id;
                }
            }
        }
    }

    fn insert_into_active_queue(&mut self, stream_id: u32) {
        if !self.active_queue.contains(&stream_id) {
            self.active_queue.push_back(stream_id);
        }
    }

    pub fn get_tree_stats(&self) -> DependencyTreeStats {
        DependencyTreeStats {
            total_streams: self.streams.len(),
            active_streams: self.active_queue.len(),
            blocked_streams: self.blocked_streams.len(),
            tree_depth: self.calculate_tree_depth(self.root_stream_id, 0),
            total_pending_bytes: self.total_pending,
        }
    }

    fn calculate_tree_depth(&self, node_id: u32, current_depth: usize) -> usize {
        if let Some(node) = self.dependencies.get(&node_id) {
            if node.children.is_empty() {
                return current_depth;
            }
            
            node.children.iter().map(|&child_id| {
                self.calculate_tree_depth(child_id, current_depth + 1)
            }).max().unwrap_or(current_depth)
        } else {
            current_depth
        }
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecurePrioritySchedulerBlobMeta, Vec<u8>)> {
        encode_secure_priority_scheduler(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecurePrioritySchedulerBlobMeta, Vec<u8>)> {
        encode_secure_priority_scheduler_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecurePrioritySchedulerBlobMeta, Self)> {
        decode_secure_priority_scheduler(data)
    }
}

pub fn select_secure_priority_scheduler_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_priority_scheduler(scheduler: &PriorityScheduler, algorithm: CompressionAlgorithm) -> io::Result<(SecurePrioritySchedulerBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_priority_scheduler(scheduler)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate scheduler blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_priority_scheduler_blob_tag(
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
        magic = PRIORITY_SCHEDULER_BLOB_MAGIC,
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
        SecurePrioritySchedulerBlobMeta {
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

pub fn encode_secure_priority_scheduler_auto(scheduler: &PriorityScheduler, accept_encoding: &str) -> io::Result<(SecurePrioritySchedulerBlobMeta, Vec<u8>)> {
    let selected = select_secure_priority_scheduler_algorithm(accept_encoding);
    encode_secure_priority_scheduler(scheduler, selected)
}

pub fn decode_secure_priority_scheduler(data: &[u8]) -> io::Result<(SecurePrioritySchedulerBlobMeta, PriorityScheduler)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_priority_scheduler_meta(&header, body.len())?;
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

    let expected_tag = compute_priority_scheduler_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "scheduler blob HMAC mismatch",
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
            "scheduler blob digest mismatch",
        ));
    }

    let scheduler = deserialize_priority_scheduler(&raw_payload)?;
    Ok((meta, scheduler))
}

fn serialize_priority_scheduler(scheduler: &PriorityScheduler) -> io::Result<Vec<u8>> {
    let mut lines = Vec::new();
    lines.push(format!("root-stream-id={}", scheduler.root_stream_id));
    lines.push(format!("total-pending={}", scheduler.total_pending));
    let active_csv = scheduler.active_queue.iter().map(|id| {
        id.to_string()
    }).collect::<Vec<_>>().join(",");

    lines.push(format!("active-queue={}", pem::encode(active_csv.as_bytes())));
    let blocked_csv = scheduler.blocked_streams.iter().map(|id| {
        id.to_string()
    }).collect::<Vec<_>>().join(",");

    lines.push(format!(
        "blocked-streams={}",
        pem::encode(blocked_csv.as_bytes())
    ));

    let mut stream_ids: Vec<u32> = scheduler.streams.keys().copied().collect();
    stream_ids.sort_unstable();
    lines.push(format!("stream-count={}", stream_ids.len()));
    for (idx, stream_id) in stream_ids.iter().enumerate() {
        let stream = scheduler.streams.get(stream_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing stream in scheduler map")
        })?;

        lines.push(format!("stream-{}-id={}", idx, stream.stream_id));
        lines.push(format!(
            "stream-{}-state={}",
            idx,
            stream_schedule_state_as_str(stream.state)
        ));

        lines.push(format!(
            "stream-{}-priority-stream-dependency={}",
            idx, stream.priority.stream_dependency
        ));

        lines.push(format!(
            "stream-{}-priority-weight={}",
            idx, stream.priority.weight
        ));

        lines.push(format!(
            "stream-{}-priority-exclusive={}",
            idx, stream.priority.exclusive
        ));

        lines.push(format!(
            "stream-{}-pending-bytes={}",
            idx, stream.pending_bytes
        ));

        lines.push(format!("stream-{}-quantum={}", idx, stream.quantum));
        lines.push(format!("stream-{}-deficit={}", idx, stream.deficit));
    }

    let mut dep_ids: Vec<u32> = scheduler.dependencies.keys().copied().collect();
    dep_ids.sort_unstable();
    lines.push(format!("dependency-count={}", dep_ids.len()));
    for (idx, dep_id) in dep_ids.iter().enumerate() {
        let dep = scheduler.dependencies.get(dep_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing dependency in scheduler map",
            )
        })?;

        let children_csv = dep.children.iter().map(|id| {
            id.to_string()
        }).collect::<Vec<_>>().join(",");

        lines.push(format!("dependency-{}-stream-id={}", idx, dep.stream_id));
        lines.push(format!("dependency-{}-parent-id={}", idx, dep.parent_id));
        lines.push(format!("dependency-{}-exclusive={}", idx, dep.exclusive));
        lines.push(format!(
            "dependency-{}-children={}",
            idx,
            pem::encode(children_csv.as_bytes())
        ));
    }

    Ok(lines.join("\n").into_bytes())
}

fn deserialize_priority_scheduler(raw_payload: &[u8]) -> io::Result<PriorityScheduler> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "scheduler payload is not valid UTF-8",
        )
    })?;

    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid scheduler payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let root_stream_id = parse_u32(required_field(&kv, "root-stream-id")?, "root-stream-id")?;
    let serialized_total_pending = parse_usize(required_field(&kv, "total-pending")?, "total-pending")?;
    let active_queue = decode_id_list(required_field(&kv, "active-queue")?, "active-queue")?;
    let blocked_streams = decode_id_list(required_field(&kv, "blocked-streams")?, "blocked-streams")?;
    let stream_count = parse_usize(required_field(&kv, "stream-count")?, "stream-count")?;
    let mut streams = HashMap::new();
    for idx in 0..stream_count {
        let id = parse_u32(
            required_field(&kv, &format!("stream-{}-id", idx))?,
            &format!("stream-{}-id", idx),
        )?;

        let state = parse_stream_schedule_state(required_field(
            &kv,
            &format!("stream-{}-state", idx),
        )?)?;
        
        let priority_dep = parse_u32(
            required_field(&kv, &format!("stream-{}-priority-stream-dependency", idx))?,
            &format!("stream-{}-priority-stream-dependency", idx),
        )?;
        
        let priority_weight = parse_u8(
            required_field(&kv, &format!("stream-{}-priority-weight", idx))?,
            &format!("stream-{}-priority-weight", idx),
        )?;
        
        let priority_exclusive = parse_bool(required_field(
            &kv,
            &format!("stream-{}-priority-exclusive", idx),
        )?)?;
        
        let pending_bytes = parse_usize(
            required_field(&kv, &format!("stream-{}-pending-bytes", idx))?,
            &format!("stream-{}-pending-bytes", idx),
        )?;
        
        let quantum = parse_usize(
            required_field(&kv, &format!("stream-{}-quantum", idx))?,
            &format!("stream-{}-quantum", idx),
        )?;
        
        let deficit = parse_i64(
            required_field(&kv, &format!("stream-{}-deficit", idx))?,
            &format!("stream-{}-deficit", idx),
        )?;

        streams.insert(
            id,
            ScheduleStream {
                stream_id: id,
                state,
                priority: Priority::new(priority_dep, priority_weight, priority_exclusive),
                pending_bytes,
                quantum,
                deficit,
            },
        );
    }

    let dependency_count = parse_usize(required_field(&kv, "dependency-count")?, "dependency-count")?;
    let mut dependencies = HashMap::new();
    for idx in 0..dependency_count {
        let stream_id = parse_u32(
            required_field(&kv, &format!("dependency-{}-stream-id", idx))?,
            &format!("dependency-{}-stream-id", idx),
        )?;

        let parent_id = parse_u32(
            required_field(&kv, &format!("dependency-{}-parent-id", idx))?,
            &format!("dependency-{}-parent-id", idx),
        )?;
        
        let exclusive = parse_bool(required_field(
            &kv,
            &format!("dependency-{}-exclusive", idx),
        )?)?;
        
        let children = decode_id_list(
            required_field(&kv, &format!("dependency-{}-children", idx))?,
            &format!("dependency-{}-children", idx),
        )?;

        dependencies.insert(
            stream_id,
            DependencyNode {
                stream_id,
                parent_id,
                children,
                exclusive,
            },
        );
    }

    if !dependencies.contains_key(&root_stream_id) {
        dependencies.insert(
            root_stream_id,
            DependencyNode::new(root_stream_id, root_stream_id, false),
        );
    }

    let active_queue: VecDeque<u32> = active_queue.into_iter().filter(|id| {
        streams.contains_key(id)
    }).collect();

    let blocked_streams: Vec<u32> = blocked_streams.into_iter().filter(|id| {
        streams.contains_key(id)
    }).collect();

    let computed_total_pending = streams.values().map(|s| s.pending_bytes).sum::<usize>();
    if serialized_total_pending != computed_total_pending {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "total-pending mismatch: payload {}, computed {}",
                serialized_total_pending, computed_total_pending
            ),
        ));
    }

    Ok(PriorityScheduler {
        streams,
        dependencies,
        root_stream_id,
        active_queue,
        blocked_streams,
        total_pending: computed_total_pending,
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in scheduler payload", key),
        )
    })
}

fn parse_u32(v: &str, field: &str) -> io::Result<u32> {
    v.parse::<u32>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_u8(v: &str, field: &str) -> io::Result<u8> {
    v.parse::<u8>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_i64(v: &str, field: &str) -> io::Result<i64> {
    v.parse::<i64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid bool '{}'", v),
        )),
    }
}

fn stream_schedule_state_as_str(state: StreamScheduleState) -> &'static str {
    match state {
        StreamScheduleState::Ready => "ready",
        StreamScheduleState::Blocked => "blocked",
        StreamScheduleState::Idle => "idle",
        StreamScheduleState::Closed => "closed",
    }
}

fn parse_stream_schedule_state(v: &str) -> io::Result<StreamScheduleState> {
    match v {
        "ready" => Ok(StreamScheduleState::Ready),
        "blocked" => Ok(StreamScheduleState::Blocked),
        "idle" => Ok(StreamScheduleState::Idle),
        "closed" => Ok(StreamScheduleState::Closed),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid stream schedule state '{}'", v),
        )),
    }
}

fn decode_id_list(encoded: &str, field: &str) -> io::Result<Vec<u32>> {
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

    text.split(',').map(|chunk| {
        chunk.trim().parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} entry '{}'", field, chunk),
            )
        })
    }).collect()
}

fn compute_priority_scheduler_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(PRIORITY_SCHEDULER_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(PRIORITY_SCHEDULER_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_priority_scheduler_meta(header: &str, body_len: usize) -> io::Result<SecurePrioritySchedulerBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != PRIORITY_SCHEDULER_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure scheduler blob magic mismatch",
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
                format!("invalid secure scheduler header line '{}'", line),
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
            "missing nonce in secure scheduler blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure scheduler blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure scheduler blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure scheduler blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure scheduler blob",
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
            "missing issued-at in secure scheduler blob",
        )
    })?;

    Ok(SecurePrioritySchedulerBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DependencyTreeStats {
    pub total_streams: usize,
    pub active_streams: usize,
    pub blocked_streams: usize,
    pub tree_depth: usize,
    pub total_pending_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = PriorityScheduler::new();
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(scheduler.total_pending_bytes(), 0);
    }

    #[test]
    fn test_add_stream() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        assert!(scheduler.streams.contains_key(&1));
    }

    #[test]
    fn test_mark_ready() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        scheduler.mark_ready(1, 1000);
        
        assert_eq!(scheduler.get_state(1), Some(StreamScheduleState::Ready));
        assert_eq!(scheduler.total_pending_bytes(), 1000);
    }

    #[test]
    fn test_schedule_single_stream() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        scheduler.mark_ready(1, 1000);
        
        let next = scheduler.schedule_next();
        assert_eq!(next, Some(1));
    }

    #[test]
    fn test_schedule_multiple_streams_by_weight() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 255, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.add_stream(3, Priority::new(0, 1, false));
        scheduler.mark_ready(3, 1000);
        
        let mut stream1_count = 0;
        let mut stream3_count = 0;
        
        for _ in 0..10 {
            if let Some(stream_id) = scheduler.schedule_next() {
                if stream_id == 1 {
                    stream1_count += 1;
                } else if stream_id == 3 {
                    stream3_count += 1;
                }
                
                scheduler.mark_ready(stream_id, 1000);
            }
        }
        
        assert!(stream1_count > stream3_count);
    }

    #[test]
    fn test_dependency_exclusive() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, true));
        scheduler.add_stream(5, Priority::new(1, 16, false));
        
        let node3 = scheduler.dependencies.get(&3).unwrap();
        assert_eq!(node3.parent_id, 1);
        assert!(node3.children.contains(&5));
        
        let node5 = scheduler.dependencies.get(&5).unwrap();
        assert_eq!(node5.parent_id, 3);
    }

    #[test]
    fn test_remove_stream_reparents_children() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        scheduler.remove_stream(3);
        
        let node5 = scheduler.dependencies.get(&5).unwrap();
        assert_eq!(node5.parent_id, 1);
    }

    #[test]
    fn test_bytes_sent() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.bytes_sent(1, 300);
        
        assert_eq!(scheduler.total_pending_bytes(), 700);
    }

    #[test]
    fn test_tree_stats() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        scheduler.mark_ready(1, 1000);
        scheduler.mark_ready(3, 2000);
        
        let stats = scheduler.get_tree_stats();
        assert_eq!(stats.total_streams, 3);
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.tree_depth, 3);
        assert_eq!(stats.total_pending_bytes, 3000);
    }

    #[test]
    fn test_secure_priority_scheduler_roundtrip_identity() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 32, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.mark_ready(1, 1200);
        scheduler.mark_ready(3, 800);
        scheduler.bytes_sent(1, 200);

        let (_meta, blob) =
            encode_secure_priority_scheduler(&scheduler, CompressionAlgorithm::Identity).unwrap();
        let (_decoded_meta, decoded) = decode_secure_priority_scheduler(&blob).unwrap();

        assert_eq!(decoded.total_pending_bytes(), scheduler.total_pending_bytes());
        assert_eq!(decoded.get_state(1), scheduler.get_state(1));
        assert_eq!(decoded.get_state(3), scheduler.get_state(3));
        assert_eq!(decoded.active_count(), scheduler.active_count());
        assert_eq!(
            decoded.get_tree_stats().tree_depth,
            scheduler.get_tree_stats().tree_depth
        );
    }

    #[test]
    fn test_secure_priority_scheduler_tamper_detected() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);

        let (_meta, mut blob) =
            encode_secure_priority_scheduler(&scheduler, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_priority_scheduler(&blob).is_err());
    }
}