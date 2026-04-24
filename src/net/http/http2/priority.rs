use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{HashMap, HashSet};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const PRIORITY_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_PRIORITY_BLOB_V1";
const PRIORITY_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_PRIORITY_BLOB_BINDING_V1";
const PRIORITY_TREE_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_PRIORITY_TREE_BLOB_V1";
const PRIORITY_TREE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_PRIORITY_TREE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePriorityBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePriorityTreeBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct Priority {
    pub stream_dependency: u32,
    pub weight: u8,
    pub exclusive: bool,
}

impl Priority {
    pub fn new(stream_dependency: u32, weight: u8, exclusive: bool) -> Self {
        Self {
            stream_dependency,
            weight,
            exclusive,
        }
    }

    pub fn parse(data: &[u8]) -> Self {
        if data.len() < 5 {
            return Self::default();
        }

        let first_dword = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let exclusive = (first_dword & 0x80000000) != 0;
        let stream_dependency = first_dword & 0x7fffffff;
        let weight = data[4];

        Self {
            stream_dependency,
            weight,
            exclusive,
        }
    }

    pub fn serialize(&self) -> [u8; 5] {
        let dependency = if self.exclusive {
            self.stream_dependency | 0x80000000
        } else {
            self.stream_dependency
        };

        let bytes = dependency.to_be_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3], self.weight]
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecurePriorityBlobMeta, Vec<u8>)> {
        encode_secure_priority(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecurePriorityBlobMeta, Vec<u8>)> {
        encode_secure_priority_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecurePriorityBlobMeta, Self)> {
        decode_secure_priority(data)
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            stream_dependency: 0,
            weight: 16,
            exclusive: false,
        }
    }
}

#[derive(Debug, Clone)]
struct PriorityNode {
    stream_id: u32,
    weight: u8,
    parent: u32,
    children: Vec<u32>,
    virtual_finish_time: u64,
}

impl PriorityNode {
    fn new(stream_id: u32, weight: u8, parent: u32) -> Self {
        Self {
            stream_id,
            weight,
            parent,
            children: Vec::new(),
            virtual_finish_time: 0,
        }
    }
}

#[derive(Debug)]
pub struct PriorityTree {
    nodes: HashMap<u32, PriorityNode>,
    root_children: Vec<u32>,
    virtual_time: u64,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_children: Vec::new(),
            virtual_time: 0,
        }
    }

    pub fn set_priority(&mut self, stream_id: u32, priority: Priority) {
        if stream_id == priority.stream_dependency {
            return;
        }

        if let Some(node) = self.nodes.get(&stream_id) {
            let old_parent = node.parent;
            self.remove_from_parent(stream_id, old_parent);
        }

        let parent_id = priority.stream_dependency;
        if priority.exclusive {
            let old_children = if let Some(parent) = self.nodes.get_mut(&parent_id) {
                std::mem::take(&mut parent.children)
            } else if parent_id == 0 {
                std::mem::take(&mut self.root_children)
            } else {
                Vec::new()
            };

            let node = self.nodes.entry(stream_id).or_insert_with(|| {
                PriorityNode::new(stream_id, priority.weight, parent_id)
            });

            node.weight = priority.weight;
            node.parent = parent_id;
            node.children = old_children.clone();
            for &child_id in &old_children {
                if let Some(child) = self.nodes.get_mut(&child_id) {
                    child.parent = stream_id;
                }
            }
        } else {
            let node = self.nodes.entry(stream_id).or_insert_with(|| {
                PriorityNode::new(stream_id, priority.weight, parent_id)
            });

            node.weight = priority.weight;
            node.parent = parent_id;
        }

        if parent_id == 0 {
            if !self.root_children.contains(&stream_id) {
                self.root_children.push(stream_id);
            }
        } else if let Some(parent) = self.nodes.get_mut(&parent_id) {
            if !parent.children.contains(&stream_id) {
                parent.children.push(stream_id);
            }
        }

        self.detect_and_break_cycles(stream_id);
    }

    pub fn remove(&mut self, stream_id: u32) {
        if let Some(node) = self.nodes.remove(&stream_id) {
            self.remove_from_parent(stream_id, node.parent);
            for child_id in node.children {
                if let Some(child) = self.nodes.get_mut(&child_id) {
                    child.parent = node.parent;
                }

                if node.parent == 0 {
                    if !self.root_children.contains(&child_id) {
                        self.root_children.push(child_id);
                    }
                } else if let Some(parent) = self.nodes.get_mut(&node.parent) {
                    if !parent.children.contains(&child_id) {
                        parent.children.push(child_id);
                    }
                }
            }
        }
    }

    pub fn next_stream(&mut self, available_streams: &[u32]) -> Option<u32> {
        if available_streams.is_empty() {
            return None;
        }

        let mut candidates = Vec::new();
        for &stream_id in available_streams {
            let effective_vft = self.calculate_effective_vft(stream_id);
            candidates.push((stream_id, effective_vft));
        }
        
        candidates.sort_by_key(|&(_, vft)| vft);
        candidates.first().map(|&(stream_id, _)| stream_id)
    }

    fn calculate_effective_vft(&self, stream_id: u32) -> u64 {
        if let Some(node) = self.nodes.get(&stream_id) {
            let mut vft = node.virtual_finish_time;
            let mut current_id = stream_id;
            while current_id != 0 {
                if let Some(parent_node) = self.nodes.get(&current_id) {
                    let weight_factor = 256 / (parent_node.weight as u64 + 1);
                    vft = vft.saturating_add(weight_factor);
                    current_id = parent_node.parent;
                } else {
                    break;
                }
            }

            vft
        } else {
            self.virtual_time
        }
    }

    pub fn update_after_send(&mut self, stream_id: u32, bytes_sent: usize) {
        let weight = self.nodes.get(&stream_id).map(|n| n.weight).unwrap_or(16) as u64;
        let service_time = (bytes_sent as u64 * 256) / weight;
        if let Some(node) = self.nodes.get_mut(&stream_id) {
            node.virtual_finish_time = self.virtual_time + service_time;
        }

        self.virtual_time += service_time;
    }

    pub fn calculate_effective_weight(&self, stream_id: u32) -> u8 {
        if let Some(node) = self.nodes.get(&stream_id) {
            let parent_id = node.parent;
            let siblings = if parent_id == 0 {
                &self.root_children
            } else if let Some(parent) = self.nodes.get(&parent_id) {
                &parent.children
            } else {
                return node.weight;
            };

            let total_weight: u32 = siblings.iter().filter_map(|&id| self.nodes.get(&id).map(|n| n.weight as u32)).sum();
            if total_weight == 0 {
                return node.weight;
            }

            let proportional = ((node.weight as u32 * 256) / total_weight) as u8; // Scaled 1-256
            proportional.max(1)
        } else {
            16 // Default
        }
    }

    pub fn get_ordered_streams(&self) -> Vec<u32> {
        let mut streams: Vec<_> = self.nodes.keys().copied().collect();
        streams.sort_by_key(|&id| self.calculate_effective_vft(id));
        streams
    }

    pub fn contains(&self, stream_id: u32) -> bool {
        self.nodes.contains_key(&stream_id)
    }

    pub fn get_weight(&self, stream_id: u32) -> Option<u8> {
        self.nodes.get(&stream_id).map(|n| n.weight)
    }

    pub fn get_parent(&self, stream_id: u32) -> Option<u32> {
        self.nodes.get(&stream_id).map(|n| n.parent)
    }

    pub fn get_children(&self, stream_id: u32) -> Vec<u32> {
        if stream_id == 0 {
            self.root_children.clone()
        } else {
            self.nodes.get(&stream_id).map(|n| n.children.clone()).unwrap_or_default()
        }
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecurePriorityTreeBlobMeta, Vec<u8>)> {
        encode_secure_priority_tree(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecurePriorityTreeBlobMeta, Vec<u8>)> {
        encode_secure_priority_tree_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecurePriorityTreeBlobMeta, Self)> {
        decode_secure_priority_tree(data)
    }

    fn remove_from_parent(&mut self, stream_id: u32, parent_id: u32) {
        if parent_id == 0 {
            self.root_children.retain(|&id| id != stream_id);
        } else if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.retain(|&id| id != stream_id);
        }
    }

    fn detect_and_break_cycles(&mut self, start_stream_id: u32) {
        let mut visited = HashSet::new();
        let mut current_id = start_stream_id;
        loop {
            if current_id == 0 {
                break;
            }

            if !visited.insert(current_id) {
                if let Some(node) = self.nodes.get_mut(&current_id) {
                    let old_parent = node.parent;
                    node.parent = 0;
                    if let Some(parent) = self.nodes.get_mut(&old_parent) {
                        parent.children.retain(|&id| id != current_id);
                    }

                    if !self.root_children.contains(&current_id) {
                        self.root_children.push(current_id);
                    }
                }

                break;
            }

            if let Some(node) = self.nodes.get(&current_id) {
                current_id = node.parent;
            } else {
                break;
            }

            if visited.len() > 1000 {
                break;
            }
        }
    }
}

impl Default for PriorityTree {
    fn default() -> Self {
        Self::new()
    }
}

pub fn select_secure_priority_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn select_secure_priority_tree_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    select_secure_priority_algorithm(accept_encoding)
}

pub fn encode_secure_priority(priority: &Priority, algorithm: CompressionAlgorithm) -> io::Result<(SecurePriorityBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_priority(priority);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate priority blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_priority_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let nonce_b64 = pem::encode(&nonce);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = PRIORITY_BLOB_MAGIC,
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
        SecurePriorityBlobMeta {
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

pub fn encode_secure_priority_auto(priority: &Priority, accept_encoding: &str) -> io::Result<(SecurePriorityBlobMeta, Vec<u8>)> {
    let selected = select_secure_priority_algorithm(accept_encoding);
    encode_secure_priority(priority, selected)
}

pub fn decode_secure_priority(data: &[u8]) -> io::Result<(SecurePriorityBlobMeta, Priority)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_priority_meta(&header, body.len())?;
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

    let expected_tag = compute_priority_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "priority blob HMAC mismatch",
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
            "priority blob digest mismatch",
        ));
    }

    let priority = deserialize_priority(&raw_payload)?;
    Ok((meta, priority))
}

pub fn encode_secure_priority_tree(tree: &PriorityTree, algorithm: CompressionAlgorithm) -> io::Result<(SecurePriorityTreeBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_priority_tree(tree)?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate priority tree blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_priority_tree_blob_tag(
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
        magic = PRIORITY_TREE_BLOB_MAGIC,
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
        SecurePriorityTreeBlobMeta {
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

pub fn encode_secure_priority_tree_auto(tree: &PriorityTree, accept_encoding: &str) -> io::Result<(SecurePriorityTreeBlobMeta, Vec<u8>)> {
    let selected = select_secure_priority_tree_algorithm(accept_encoding);
    encode_secure_priority_tree(tree, selected)
}

pub fn decode_secure_priority_tree(data: &[u8]) -> io::Result<(SecurePriorityTreeBlobMeta, PriorityTree)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_priority_tree_meta(&header, body.len())?;
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

    let expected_tag = compute_priority_tree_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "priority tree blob HMAC mismatch",
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
            "priority tree blob digest mismatch",
        ));
    }

    let tree = deserialize_priority_tree(&raw_payload)?;
    Ok((meta, tree))
}

fn serialize_priority(priority: &Priority) -> Vec<u8> {
    priority.serialize().to_vec()
}

fn deserialize_priority(raw_payload: &[u8]) -> io::Result<Priority> {
    if raw_payload.len() != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid priority payload size: expected 5, got {}",
                raw_payload.len()
            ),
        ));
    }

    Ok(Priority::parse(raw_payload))
}

fn serialize_priority_tree(tree: &PriorityTree) -> io::Result<Vec<u8>> {
    let mut lines = Vec::new();
    lines.push(format!("virtual-time={}", tree.virtual_time));
    lines.push(format!(
        "root-children={}",
        encode_id_list(&tree.root_children)
    ));

    let mut node_ids: Vec<u32> = tree.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    lines.push(format!("node-count={}", node_ids.len()));
    for (idx, node_id) in node_ids.iter().enumerate() {
        let node = tree.nodes.get(node_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing node in priority tree")
        })?;

        lines.push(format!("node-{}-stream-id={}", idx, node.stream_id));
        lines.push(format!("node-{}-weight={}", idx, node.weight));
        lines.push(format!("node-{}-parent={}", idx, node.parent));
        lines.push(format!(
            "node-{}-virtual-finish-time={}",
            idx, node.virtual_finish_time
        ));

        lines.push(format!(
            "node-{}-children={}",
            idx,
            encode_id_list(&node.children)
        ));
    }

    Ok(lines.join("\n").into_bytes())
}

fn deserialize_priority_tree(raw_payload: &[u8]) -> io::Result<PriorityTree> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "priority tree payload is not valid UTF-8",
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
                format!("invalid priority tree payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let virtual_time = parse_u64(required_field(&kv, "virtual-time")?, "virtual-time")?;
    let root_children = decode_id_list(required_field(&kv, "root-children")?, "root-children")?;
    let node_count = parse_u64(required_field(&kv, "node-count")?, "node-count")? as usize;
    let mut nodes = HashMap::new();
    for idx in 0..node_count {
        let stream_id = parse_u32(
            required_field(&kv, &format!("node-{}-stream-id", idx))?,
            &format!("node-{}-stream-id", idx),
        )?;

        let weight = parse_u8(
            required_field(&kv, &format!("node-{}-weight", idx))?,
            &format!("node-{}-weight", idx),
        )?;

        let parent = parse_u32(
            required_field(&kv, &format!("node-{}-parent", idx))?,
            &format!("node-{}-parent", idx),
        )?;

        let virtual_finish_time = parse_u64(
            required_field(&kv, &format!("node-{}-virtual-finish-time", idx))?,
            &format!("node-{}-virtual-finish-time", idx),
        )?;

        let children = decode_id_list(
            required_field(&kv, &format!("node-{}-children", idx))?,
            &format!("node-{}-children", idx),
        )?;

        let node = PriorityNode {
            stream_id,
            weight,
            parent,
            children,
            virtual_finish_time,
        };

        if nodes.insert(stream_id, node).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate node stream id '{}'", stream_id),
            ));
        }
    }

    Ok(PriorityTree {
        nodes,
        root_children,
        virtual_time,
    })
}

fn encode_id_list(ids: &[u32]) -> String {
    let csv = ids.iter().map(|id| {
        id.to_string()
    }).collect::<Vec<_>>().join(",");

    pem::encode(csv.as_bytes())
}

fn decode_id_list(encoded: &str, field: &str) -> io::Result<Vec<u32>> {
    let raw = pem::decode(encoded).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid base64 for '{}': {}", field, e),
        )
    })?;

    let csv = String::from_utf8(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid UTF-8 in '{}'", field),
        )
    })?;

    if csv.trim().is_empty() {
        return Ok(Vec::new());
    }

    csv.split(',').filter(|part| !part.trim().is_empty()).map(|part| {
        parse_u32(part.trim(), field)
    }).collect()
}

fn compute_priority_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(PRIORITY_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(PRIORITY_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn compute_priority_tree_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(PRIORITY_TREE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(PRIORITY_TREE_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_priority_meta(header: &str, body_len: usize) -> io::Result<SecurePriorityBlobMeta> {
    parse_secure_meta_common(PRIORITY_BLOB_MAGIC, header, body_len).map(
        |(algorithm, nonce_b64, digest_b64, tag_b64, raw_size, encoded_size, issued_at_unix)| {
            SecurePriorityBlobMeta {
                algorithm,
                nonce_b64,
                digest_b64,
                tag_b64,
                raw_size,
                encoded_size,
                issued_at_unix,
            }
        },
    )
}

fn parse_secure_priority_tree_meta(header: &str, body_len: usize) -> io::Result<SecurePriorityTreeBlobMeta> {
    parse_secure_meta_common(PRIORITY_TREE_BLOB_MAGIC, header, body_len).map(
        |(algorithm, nonce_b64, digest_b64, tag_b64, raw_size, encoded_size, issued_at_unix)| {
            SecurePriorityTreeBlobMeta {
                algorithm,
                nonce_b64,
                digest_b64,
                tag_b64,
                raw_size,
                encoded_size,
                issued_at_unix,
            }
        },
    )
}

fn parse_secure_meta_common(expected_magic: &str, header: &str, body_len: usize) -> io::Result<(CompressionAlgorithm, String, String, String, usize, usize, u64)> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != expected_magic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure blob magic mismatch",
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
                format!("invalid secure blob header line '{}'", line),
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
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing encoded-size in secure blob")
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
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in secure blob")
    })?;

    Ok((
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    ))
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("missing field '{}'", key))
    })
}

fn parse_u8(value: &str, field: &str) -> io::Result<u8> {
    value.parse::<u8>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid '{}' value '{}'", field, value),
        )
    })
}

fn parse_u32(value: &str, field: &str) -> io::Result<u32> {
    value.parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid '{}' value '{}'", field, value),
        )
    })
}

fn parse_u64(value: &str, field: &str) -> io::Result<u64> {
    value.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid '{}' value '{}'", field, value),
        )
    })
}

fn parse_bool(value: &str, field: &str) -> io::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid '{}' value '{}'", field, value),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_parse() {
        let data = [0x80, 0x00, 0x00, 0x05, 0x20];
        let priority = Priority::parse(&data);
        
        assert!(priority.exclusive);
        assert_eq!(priority.stream_dependency, 5);
        assert_eq!(priority.weight, 32);
    }

    #[test]
    fn test_priority_serialize() {
        let priority = Priority::new(5, 32, true);
        let data = priority.serialize();
        
        assert_eq!(data, [0x80, 0x00, 0x00, 0x05, 0x20]);
    }

    #[test]
    fn test_priority_tree_basic() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::default());
        assert!(tree.contains(1));
        assert_eq!(tree.get_weight(1), Some(16));
        
        tree.set_priority(3, Priority::new(1, 32, false));
        assert_eq!(tree.get_parent(3), Some(1));
        assert_eq!(tree.get_weight(3), Some(32));
    }

    #[test]
    fn test_priority_tree_exclusive() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(0, 16, false));
        
        assert_eq!(tree.get_children(0), vec![1, 3]);
        
        tree.set_priority(5, Priority::new(0, 32, true));
        
        assert_eq!(tree.get_parent(1), Some(5));
        assert_eq!(tree.get_parent(3), Some(5));
        assert_eq!(tree.get_parent(5), Some(0));
    }

    #[test]
    fn test_priority_tree_cycle_prevention() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(1, 16, false));
        tree.set_priority(5, Priority::new(3, 16, false));
        
        tree.set_priority(1, Priority::new(5, 16, false));
        
        assert_ne!(tree.get_parent(1), Some(5));
    }

    #[test]
    fn test_priority_tree_self_dependency() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(1, 16, false));
        
        if tree.contains(1) {
            assert_ne!(tree.get_parent(1), Some(1));
        }
    }

    #[test]
    fn test_weighted_fair_queuing() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 32, false));
        tree.set_priority(3, Priority::new(0, 8, false));
        
        let available = vec![1, 3];
        
        let next = tree.next_stream(&available);
        assert_eq!(next, Some(1));
        
        tree.update_after_send(1, 1000);
        
        let next = tree.next_stream(&available);
        assert!(next == Some(1) || next == Some(3));
    }

    #[test]
    fn test_priority_tree_remove() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(1, 16, false));
        tree.set_priority(5, Priority::new(1, 16, false));
        
        assert_eq!(tree.get_children(1), vec![3, 5]);
        
        tree.remove(1);
        
        assert!(!tree.contains(1));
        assert_eq!(tree.get_parent(3), Some(0));
        assert_eq!(tree.get_parent(5), Some(0));
    }

    #[test]
    fn test_effective_weight() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 64, false));
        tree.set_priority(3, Priority::new(0, 32, false));
        
        let weight1 = tree.calculate_effective_weight(1);
        let weight3 = tree.calculate_effective_weight(3);
        
        assert!(weight1 > weight3);
    }

    #[test]
    fn test_get_ordered_streams() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 64, false));
        tree.set_priority(3, Priority::new(0, 32, false));
        tree.set_priority(5, Priority::new(0, 16, false));
        
        let ordered = tree.get_ordered_streams();
        
        assert_eq!(ordered.len(), 3);
        assert!(ordered.contains(&1));
        assert!(ordered.contains(&3));
        assert!(ordered.contains(&5));
    }

    #[test]
    fn test_secure_priority_roundtrip_identity() {
        let priority = Priority::new(5, 32, true);

        let (meta, blob) = encode_secure_priority(&priority, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.raw_size, 5);

        let (decoded_meta, decoded_priority) = decode_secure_priority(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_priority.stream_dependency, priority.stream_dependency);
        assert_eq!(decoded_priority.weight, priority.weight);
        assert_eq!(decoded_priority.exclusive, priority.exclusive);
    }

    #[test]
    fn test_secure_priority_tamper_detected() {
        let priority = Priority::new(7, 64, false);
        let (_meta, mut blob) =
            encode_secure_priority(&priority, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_priority(&blob).is_err());
    }

    #[test]
    fn test_secure_priority_tree_roundtrip_identity() {
        let mut tree = PriorityTree::new();
        tree.set_priority(1, Priority::new(0, 64, false));
        tree.set_priority(3, Priority::new(1, 32, false));
        tree.set_priority(5, Priority::new(1, 16, false));
        tree.update_after_send(1, 128);

        let (meta, blob) =
            encode_secure_priority_tree(&tree, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert!(meta.raw_size > 0);

        let (decoded_meta, decoded_tree) = decode_secure_priority_tree(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert!(decoded_tree.contains(1));
        assert!(decoded_tree.contains(3));
        assert!(decoded_tree.contains(5));
        assert_eq!(decoded_tree.get_parent(3), Some(1));
        assert_eq!(decoded_tree.get_parent(5), Some(1));
        assert_eq!(decoded_tree.get_weight(1), Some(64));
        assert_eq!(decoded_tree.get_children(1), vec![3, 5]);
    }

    #[test]
    fn test_secure_priority_tree_tamper_detected() {
        let mut tree = PriorityTree::new();
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(1, 16, false));

        let (_meta, mut blob) =
            encode_secure_priority_tree(&tree, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(decode_secure_priority_tree(&blob).is_err());
    }
}