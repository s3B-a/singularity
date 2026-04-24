use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const ALPN_NEGOTIATOR_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_ALPN_NEGOTIATOR_BLOB_V1";
const ALPN_NEGOTIATOR_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_ALPN_NEGOTIATOR_BLOB_BINDING_V1";
const NPN_NEGOTIATOR_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_NPN_NEGOTIATOR_BLOB_V1";
const NPN_NEGOTIATOR_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_NPN_NEGOTIATOR_BLOB_BINDING_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    Http2,
    Http11,
    Http10,
    Http3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpnProtocol {
    Http2,
    Http11,
}

#[derive(Debug, Clone)]
pub struct AlpnNegotiator {
    supported_protocols: Vec<AlpnProtocol>,
    selected_protocol: Option<AlpnProtocol>,
    server_preference: bool,
}

#[derive(Debug, Clone)]
pub struct NpnNegotiator {
    supported_protocols: Vec<NpnProtocol>,
    selected_protocol: Option<NpnProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureAlpnNegotiatorBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureNpnNegotiatorBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

impl AlpnProtocol {
    pub fn wire_format(&self) -> &'static [u8] {
        match self {
            AlpnProtocol::Http2 => b"h2",
            AlpnProtocol::Http11 => b"http/1.1",
            AlpnProtocol::Http10 => b"http/1.0",
            AlpnProtocol::Http3 => b"h3",
        }
    }

    pub fn from_wire(data: &[u8]) -> Option<Self> {
        match data {
            b"h2" => Some(AlpnProtocol::Http2),
            b"http/1.1" => Some(AlpnProtocol::Http11),
            b"http/1.0" => Some(AlpnProtocol::Http10),
            b"h3" => Some(AlpnProtocol::Http3),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AlpnProtocol::Http2 => "HTTP/2",
            AlpnProtocol::Http11 => "HTTP/1.1",
            AlpnProtocol::Http10 => "HTTP/1.0",
            AlpnProtocol::Http3 => "HTTP/3",
        }
    }

    pub fn supports_push(&self) -> bool {
        matches!(self, AlpnProtocol::Http2 | AlpnProtocol::Http3)
    }

    pub fn requires_tls(&self) -> bool {
        matches!(self, AlpnProtocol::Http2 | AlpnProtocol::Http3)
    }

    pub fn priority(&self) -> u8 {
        match self {
            AlpnProtocol::Http3 => 100,
            AlpnProtocol::Http2 => 90,
            AlpnProtocol::Http11 => 50,
            AlpnProtocol::Http10 => 10,
        }
    }
}

impl AlpnNegotiator {
    pub fn new() -> Self {
        Self {
            supported_protocols: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
            selected_protocol: None,
            server_preference: true,
        }
    }

    pub fn with_protocols(protocols: Vec<AlpnProtocol>) -> Self {
        let mut negotiator = Self::new();
        negotiator.supported_protocols = protocols;

        negotiator
    }

    pub fn set_server_preference(&mut self, enabled: bool) {
        self.server_preference = enabled;
    }

    pub fn add_protocol(&mut self, protocol: AlpnProtocol) {
        if !self.supported_protocols.contains(&protocol) {
            self.supported_protocols.push(protocol);
            self.sort_protocols();
        }
    }

    pub fn remove_protocol(&mut self, protocol: AlpnProtocol) {
        self.supported_protocols.retain(|&p| p != protocol);
    }

    pub fn supported_protocols_wire(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for protocol in &self.supported_protocols {
            let wire = protocol.wire_format();
            result.push(wire.len() as u8);
            result.extend_from_slice(wire);
        }

        result
    }

    pub fn negotiate(&mut self, client_protocols: &[u8]) -> Result<AlpnProtocol, String> {
        let client_prefs = Self::parse_protocol_list(client_protocols)
            .ok_or_else(|| "Failed to parse client ALPN protocols".to_string())?;

        if client_prefs.is_empty() {
            return Err("Client provided no ALPN protocols".to_string());
        }

        let selected = if self.server_preference {
            self.select_with_server_preference(&client_prefs)
        } else {
            self.select_with_client_preference(&client_prefs)
        };

        self.selected_protocol = selected;

        selected.ok_or_else(|| {
            let server_protos: Vec<&str> = self.supported_protocols.iter().map(|p| p.name()).collect();
            let client_protos: Vec<&str> = client_prefs.iter().map(|p| p.name()).collect();

            format!(
                "No common ALPN protocols. Server: {:?}, Client: {:?}",
                server_protos, client_protos
            )
        })
    }

    fn parse_protocol_list(data: &[u8]) -> Option<Vec<AlpnProtocol>> {
        let mut protocols = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return None;
            }

            if let Some(protocol) = AlpnProtocol::from_wire(&data[pos..pos + len]) {
                protocols.push(protocol);
            }

            pos += len;
        }

        if protocols.is_empty() {
            None
        } else {
            Some(protocols)
        }
    }

    fn select_with_server_preference(&self, client_prefs: &[AlpnProtocol]) -> Option<AlpnProtocol> {
        for &server_proto in &self.supported_protocols {
            if client_prefs.contains(&server_proto) {
                return Some(server_proto);
            }
        }

        None
    }

    fn select_with_client_preference(&self, client_prefs: &[AlpnProtocol]) -> Option<AlpnProtocol> {
        for &client_proto in client_prefs {
            if self.supported_protocols.contains(&client_proto) {
                return Some(client_proto);
            }
        }

        None
    }

    pub fn selected(&self) -> Option<AlpnProtocol> {
        self.selected_protocol
    }

    pub fn selected_wire(&self) -> Option<&'static [u8]> {
        self.selected_protocol.map(|p| p.wire_format())
    }

    pub fn is_negotiated(&self) -> bool {
        self.selected_protocol.is_some()
    }

    fn sort_protocols(&mut self) {
        self.supported_protocols.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    pub fn supported_protocols_sorted(&self) -> Vec<AlpnProtocol> {
        let mut protocols = self.supported_protocols.clone();
        protocols.sort_by(|a, b| b.priority().cmp(&a.priority()));
        protocols
    }

    pub fn reset(&mut self) {
        self.selected_protocol = None;
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureAlpnNegotiatorBlobMeta, Vec<u8>)> {
        encode_secure_alpn_negotiator(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureAlpnNegotiatorBlobMeta, Vec<u8>)> {
        encode_secure_alpn_negotiator_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureAlpnNegotiatorBlobMeta, Self)> {
        decode_secure_alpn_negotiator(data)
    }
}

impl NpnProtocol {
    pub fn wire_format(&self) -> &'static [u8] {
        match self {
            NpnProtocol::Http2 => b"h2",
            NpnProtocol::Http11 => b"http/1.1",
        }
    }

    pub fn from_wire(data: &[u8]) -> Option<Self> {
        match data {
            b"h2" => Some(NpnProtocol::Http2),
            b"http/1.1" => Some(NpnProtocol::Http11),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            NpnProtocol::Http2 => "HTTP/2",
            NpnProtocol::Http11 => "HTTP/1.1",
        }
    }
}

impl NpnNegotiator {
    pub fn new() -> Self {
        Self {
            supported_protocols: vec![NpnProtocol::Http2, NpnProtocol::Http11],
            selected_protocol: None,
        }
    }

    pub fn with_protocols(protocols: Vec<NpnProtocol>) -> Self {
        Self {
            supported_protocols: protocols,
            selected_protocol: None,
        }
    }

    pub fn supported_protocols_wire(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for protocol in &self.supported_protocols {
            let wire = protocol.wire_format();
            result.push(wire.len() as u8);
            result.extend_from_slice(wire);
        }

        result
    }

    pub fn negotiate(&mut self, server_protocols: &[u8]) -> Option<NpnProtocol> {
        let server_prefs = Self::parse_protocol_list(server_protocols)?;
        let selected = server_prefs.into_iter().find(|p| self.supported_protocols.contains(p));
        self.selected_protocol = selected;
        selected
    }

    fn parse_protocol_list(data: &[u8]) -> Option<Vec<NpnProtocol>> {
        let mut protocols = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return None;
            }

            if let Some(protocol) = NpnProtocol::from_wire(&data[pos..pos + len]) {
                protocols.push(protocol);
            }

            pos += len;
        }

        if protocols.is_empty() {
            None
        } else {
            Some(protocols)
        }
    }

    pub fn selected(&self) -> Option<NpnProtocol> {
        self.selected_protocol
    }

    pub fn reset(&mut self) {
        self.selected_protocol = None;
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureNpnNegotiatorBlobMeta, Vec<u8>)> {
        encode_secure_npn_negotiator(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureNpnNegotiatorBlobMeta, Vec<u8>)> {
        encode_secure_npn_negotiator_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureNpnNegotiatorBlobMeta, Self)> {
        decode_secure_npn_negotiator(data)
    }
}

impl fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for AlpnNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for NpnNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn select_secure_alpn_negotiator_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_alpn_negotiator(negotiator: &AlpnNegotiator, algorithm: CompressionAlgorithm) -> io::Result<(SecureAlpnNegotiatorBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_alpn_negotiator(negotiator);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate ALPN negotiator blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_alpn_negotiator_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = ALPN_NEGOTIATOR_BLOB_MAGIC,
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
        SecureAlpnNegotiatorBlobMeta {
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

pub fn encode_secure_alpn_negotiator_auto(negotiator: &AlpnNegotiator, accept_encoding: &str) -> io::Result<(SecureAlpnNegotiatorBlobMeta, Vec<u8>)> {
    let selected = select_secure_alpn_negotiator_algorithm(accept_encoding);
    encode_secure_alpn_negotiator(negotiator, selected)
}

pub fn decode_secure_alpn_negotiator(data: &[u8]) -> io::Result<(SecureAlpnNegotiatorBlobMeta, AlpnNegotiator)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_alpn_negotiator_meta(&header, body.len())?;
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

    let expected_tag = compute_alpn_negotiator_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ALPN negotiator blob HMAC mismatch",
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
            "ALPN negotiator blob digest mismatch",
        ));
    }

    let negotiator = deserialize_alpn_negotiator(&raw_payload)?;
    Ok((meta, negotiator))
}

pub fn select_secure_npn_negotiator_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_npn_negotiator(negotiator: &NpnNegotiator, algorithm: CompressionAlgorithm) -> io::Result<(SecureNpnNegotiatorBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_npn_negotiator(negotiator);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate NPN negotiator blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_npn_negotiator_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = NPN_NEGOTIATOR_BLOB_MAGIC,
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
        SecureNpnNegotiatorBlobMeta {
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

pub fn encode_secure_npn_negotiator_auto(negotiator: &NpnNegotiator, accept_encoding: &str) -> io::Result<(SecureNpnNegotiatorBlobMeta, Vec<u8>)> {
    let selected = select_secure_npn_negotiator_algorithm(accept_encoding);
    encode_secure_npn_negotiator(negotiator, selected)
}

pub fn decode_secure_npn_negotiator(data: &[u8]) -> io::Result<(SecureNpnNegotiatorBlobMeta, NpnNegotiator)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_npn_negotiator_meta(&header, body.len())?;
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

    let expected_tag = compute_npn_negotiator_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NPN negotiator blob HMAC mismatch",
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
            "NPN negotiator blob digest mismatch",
        ));
    }

    let negotiator = deserialize_npn_negotiator(&raw_payload)?;
    Ok((meta, negotiator))
}

fn serialize_alpn_negotiator(negotiator: &AlpnNegotiator) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!(
        "server-preference={}",
        if negotiator.server_preference { "1" } else { "0" }
    ));

    let selected = negotiator.selected_protocol.map(|p| pem::encode(p.wire_format())).unwrap_or_default();
    lines.push(format!("selected={}", selected));
    for protocol in &negotiator.supported_protocols {
        lines.push(format!("p={}", pem::encode(protocol.wire_format())));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_alpn_negotiator(raw_payload: &[u8]) -> io::Result<AlpnNegotiator> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ALPN negotiator payload is not valid UTF-8",
        )
    })?;

    let mut supported_protocols = Vec::new();
    let mut selected_protocol = None;
    let mut server_preference = true;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("server-preference=") {
            server_preference = parse_bool(v)?;
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("selected=") {
            let selected_encoded = v.trim();
            if !selected_encoded.is_empty() {
                let decoded = pem::decode(selected_encoded).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid selected protocol encoding: {}", e),
                    )
                })?;

                selected_protocol = AlpnProtocol::from_wire(&decoded);
            }
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("p=") {
            let decoded = pem::decode(v.trim()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid supported protocol encoding: {}", e),
                )
            })?;

            let protocol = AlpnProtocol::from_wire(&decoded).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported ALPN protocol in payload",
                )
            })?;

            if !supported_protocols.contains(&protocol) {
                supported_protocols.push(protocol);
            }
        }
    }

    if supported_protocols.is_empty() {
        supported_protocols = vec![AlpnProtocol::Http2, AlpnProtocol::Http11];
    }

    if let Some(selected) = selected_protocol {
        if !supported_protocols.contains(&selected) {
            supported_protocols.push(selected);
        }
    }

    Ok(AlpnNegotiator {
        supported_protocols,
        selected_protocol,
        server_preference,
    })
}

fn serialize_npn_negotiator(negotiator: &NpnNegotiator) -> Vec<u8> {
    let mut lines = Vec::new();

    let selected = negotiator.selected_protocol.map(|p| pem::encode(p.wire_format())).unwrap_or_default();
    lines.push(format!("selected={}", selected));
    for protocol in &negotiator.supported_protocols {
        lines.push(format!("p={}", pem::encode(protocol.wire_format())));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_npn_negotiator(raw_payload: &[u8]) -> io::Result<NpnNegotiator> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "NPN negotiator payload is not valid UTF-8",
        )
    })?;

    let mut supported_protocols = Vec::new();
    let mut selected_protocol = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("selected=") {
            let selected_encoded = v.trim();
            if !selected_encoded.is_empty() {
                let decoded = pem::decode(selected_encoded).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid selected protocol encoding: {}", e),
                    )
                })?;

                selected_protocol = NpnProtocol::from_wire(&decoded);
            }

            continue;
        }

        if let Some(v) = trimmed.strip_prefix("p=") {
            let decoded = pem::decode(v.trim()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid supported protocol encoding: {}", e),
                )
            })?;

            let protocol = NpnProtocol::from_wire(&decoded).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported NPN protocol in payload",
                )
            })?;

            if !supported_protocols.contains(&protocol) {
                supported_protocols.push(protocol);
            }
        }
    }

    if supported_protocols.is_empty() {
        supported_protocols = vec![NpnProtocol::Http2, NpnProtocol::Http11];
    }

    if let Some(selected) = selected_protocol {
        if !supported_protocols.contains(&selected) {
            supported_protocols.push(selected);
        }
    }

    Ok(NpnNegotiator {
        supported_protocols,
        selected_protocol,
    })
}

fn compute_alpn_negotiator_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(ALPN_NEGOTIATOR_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(ALPN_NEGOTIATOR_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn compute_npn_negotiator_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(NPN_NEGOTIATOR_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(NPN_NEGOTIATOR_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_alpn_negotiator_meta(header: &str, body_len: usize) -> io::Result<SecureAlpnNegotiatorBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != ALPN_NEGOTIATOR_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure ALPN negotiator blob magic mismatch",
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
                format!("invalid secure ALPN header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    },
                )?;
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
            "missing nonce in secure ALPN blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure ALPN blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure ALPN blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure ALPN blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure ALPN blob",
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
            "missing issued-at in secure ALPN blob",
        )
    })?;

    Ok(SecureAlpnNegotiatorBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

fn parse_secure_npn_negotiator_meta(header: &str, body_len: usize) -> io::Result<SecureNpnNegotiatorBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != NPN_NEGOTIATOR_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure NPN negotiator blob magic mismatch",
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
                format!("invalid secure NPN header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    },
                )?;
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
            "missing nonce in secure NPN blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure NPN blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure NPN blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure NPN blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure NPN blob",
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
            "missing issued-at in secure NPN blob",
        )
    })?;

    Ok(SecureNpnNegotiatorBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean '{}'", v),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_protocol_wire_format() {
        assert_eq!(AlpnProtocol::Http2.wire_format(), b"h2");
        assert_eq!(AlpnProtocol::Http11.wire_format(), b"http/1.1");
        assert_eq!(AlpnProtocol::Http3.wire_format(), b"h3");
    }

    #[test]
    fn test_alpn_protocol_from_wire() {
        assert_eq!(AlpnProtocol::from_wire(b"h2"), Some(AlpnProtocol::Http2));
        assert_eq!(
            AlpnProtocol::from_wire(b"http/1.1"),
            Some(AlpnProtocol::Http11)
        );
        assert_eq!(AlpnProtocol::from_wire(b"invalid"), None);
    }

    #[test]
    fn test_alpn_protocol_priority() {
        assert!(AlpnProtocol::Http3.priority() > AlpnProtocol::Http2.priority());
        assert!(AlpnProtocol::Http2.priority() > AlpnProtocol::Http11.priority());
        assert!(AlpnProtocol::Http11.priority() > AlpnProtocol::Http10.priority());
    }

    #[test]
    fn test_alpn_negotiator_new() {
        let negotiator = AlpnNegotiator::new();
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http2));
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http11));
        assert!(!negotiator.is_negotiated());
    }

    #[test]
    fn test_alpn_negotiator_add_protocol() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.add_protocol(AlpnProtocol::Http3);
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http3));
    }

    #[test]
    fn test_alpn_supported_protocols_wire() {
        let negotiator = AlpnNegotiator::new();
        let wire = negotiator.supported_protocols_wire();
        assert!(!wire.is_empty());
        assert_eq!(wire[0], 2);
    }

    #[test]
    fn test_alpn_negotiate_server_preference() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.set_server_preference(true);

        let client_prefs = b"\x08http/1.1\x02h2";
        let selected = negotiator.negotiate(client_prefs);

        assert_eq!(selected, Ok(AlpnProtocol::Http2));
        assert!(negotiator.is_negotiated());
    }

    #[test]
    fn test_alpn_negotiate_client_preference() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.set_server_preference(false);

        let client_prefs = b"\x08http/1.1\x02h2";
        let selected = negotiator.negotiate(client_prefs);

        assert_eq!(selected, Ok(AlpnProtocol::Http11));
    }

    #[test]
    fn test_alpn_negotiate_no_match() {
        let mut negotiator = AlpnNegotiator::new();

        let client_prefs = b"\x02h3";
        let selected = negotiator.negotiate(client_prefs);

        assert!(selected.is_err());
    }

    #[test]
    fn test_alpn_parse_protocol_list() {
        let protocols = AlpnNegotiator::new().supported_protocols_wire();
        assert!(!protocols.is_empty());
    }

    #[test]
    fn test_alpn_reset() {
        let mut negotiator = AlpnNegotiator::new();
        let client_prefs = b"\x02h2";
        negotiator.negotiate(client_prefs).ok();
        assert!(negotiator.is_negotiated());

        negotiator.reset();
        assert!(!negotiator.is_negotiated());
    }

    #[test]
    fn test_npn_protocol_wire_format() {
        assert_eq!(NpnProtocol::Http2.wire_format(), b"h2");
        assert_eq!(NpnProtocol::Http11.wire_format(), b"http/1.1");
    }

    #[test]
    fn test_npn_negotiator_new() {
        let negotiator = NpnNegotiator::new();
        assert!(negotiator.supported_protocols.contains(&NpnProtocol::Http2));
    }

    #[test]
    fn test_npn_negotiate() {
        let mut negotiator = NpnNegotiator::new();
        let server_prefs = b"\x02h2\x08http/1.1";
        let selected = negotiator.negotiate(server_prefs);

        assert_eq!(selected, Some(NpnProtocol::Http2));
    }

    #[test]
    fn test_alpn_protocol_requirements() {
        assert!(AlpnProtocol::Http2.requires_tls());
        assert!(AlpnProtocol::Http3.requires_tls());
        assert!(!AlpnProtocol::Http11.requires_tls());
        assert!(!AlpnProtocol::Http10.requires_tls());
    }

    #[test]
    fn test_alpn_protocol_push_support() {
        assert!(AlpnProtocol::Http2.supports_push());
        assert!(AlpnProtocol::Http3.supports_push());
        assert!(!AlpnProtocol::Http11.supports_push());
        assert!(!AlpnProtocol::Http10.supports_push());
    }

    #[test]
    fn test_alpn_sorted_protocols() {
        let negotiator = AlpnNegotiator::new();
        let sorted = negotiator.supported_protocols_sorted();
        for i in 0..sorted.len() - 1 {
            assert!(sorted[i].priority() >= sorted[i + 1].priority());
        }
    }

    #[test]
    fn test_secure_alpn_roundtrip_identity() {
        let negotiator = AlpnNegotiator::new();
        let (meta, blob) = encode_secure_alpn_negotiator(&negotiator, CompressionAlgorithm::Identity)
            .expect("encode failed");
        let (decoded_meta, decoded) =
            decode_secure_alpn_negotiator(&blob).expect("decode failed");

        assert_eq!(meta.algorithm, decoded_meta.algorithm);
        assert_eq!(decoded.supported_protocols, negotiator.supported_protocols);
        assert_eq!(decoded.server_preference, negotiator.server_preference);
    }

    #[test]
    fn test_secure_npn_roundtrip_identity() {
        let negotiator = NpnNegotiator::new();
        let (meta, blob) = encode_secure_npn_negotiator(&negotiator, CompressionAlgorithm::Identity)
            .expect("encode failed");
        let (decoded_meta, decoded) = decode_secure_npn_negotiator(&blob).expect("decode failed");

        assert_eq!(meta.algorithm, decoded_meta.algorithm);
        assert_eq!(decoded.supported_protocols, negotiator.supported_protocols);
    }
}