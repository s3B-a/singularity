use super::error::{Error, Result};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::VecDeque;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

const QPACK_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_QPACK_BLOB_V1";
const QPACK_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_QPACK_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureQpackBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
struct DynamicTableEntry {
    name: String,
    value: String,
    size: usize,
}

#[derive(Debug)]
pub struct QpackEncoder {
    dynamic_table: VecDeque<DynamicTableEntry>,
    max_table_capacity: usize,
    current_table_size: usize,
    insert_count: u64,
}

#[derive(Debug)]
pub struct QpackDecoder {
    dynamic_table: VecDeque<DynamicTableEntry>,
    max_table_capacity: usize,
    current_table_size: usize,
    insert_count: u64,
}

impl DynamicTableEntry {
    fn new(name: String, value: String) -> Self {
        let size = 32 + name.len() + value.len();
        Self { name, value, size }
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl QpackEncoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            max_table_capacity,
            current_table_size: 0,
            insert_count: 0,
        }
    }

    pub fn encode(&mut self, headers: &[(String, String)]) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        let required_insert_count = 0u64;
        let base = 0u64;
        
        Self::encode_prefix_int(&mut encoded, required_insert_count, 8);
        if required_insert_count > 0 {
            let delta = required_insert_count.saturating_sub(base);
            let negative = false;
            
            let sign_bit = if negative { 1 } else { 0 };
            Self::encode_prefix_int(&mut encoded, (delta << 1) | sign_bit, 7);
        }
        
        for (name, value) in headers {
            if let Some(static_idx) = self.find_in_static_table(name, value) {
                Self::encode_indexed_field_line(&mut encoded, static_idx, false);
            } else if let Some(static_name_idx) = self.find_name_in_static_table(name) {
                Self::encode_literal_with_name_ref(&mut encoded, static_name_idx, value, false, false);
            } else {
                Self::encode_literal_field_line(&mut encoded, name, value, false);
            }
        }
        
        Ok(encoded)
    }

    fn encode_indexed_field_line(buffer: &mut Vec<u8>, index: usize, dynamic: bool) {
        let prefix = if dynamic { 0x80 } else { 0xC0 };
        let prefix_bits = 6;
        let mut first_byte = prefix;
        if index < (1 << prefix_bits) {
            first_byte |= index as u8;
            buffer.push(first_byte);
        } else {
            first_byte |= ((1 << prefix_bits) - 1) as u8;
            buffer.push(first_byte);
            Self::encode_int(buffer, index - ((1 << prefix_bits) - 1));
        }
    }

    fn encode_literal_with_name_ref(buffer: &mut Vec<u8>, name_index: usize, value: &str, dynamic: bool, never_indexed: bool) {
        let prefix = if never_indexed {
            0x20
        } else if dynamic {
            0x40
        } else {
            0x50
        };
        
        let prefix_bits = 4;
        let mut first_byte = prefix;
        if name_index < (1 << prefix_bits) {
            first_byte |= name_index as u8;
            buffer.push(first_byte);
        } else {
            first_byte |= ((1 << prefix_bits) - 1) as u8;
            buffer.push(first_byte);
            Self::encode_int(buffer, name_index - ((1 << prefix_bits) - 1));
        }
        
        Self::encode_string(buffer, value, false);
    }

    fn encode_literal_field_line(buffer: &mut Vec<u8>, name: &str, value: &str, never_indexed: bool) {
        let prefix = if never_indexed { 0x20 } else { 0x50 };
        buffer.push(prefix);
        
        Self::encode_string(buffer, name, false);
        Self::encode_string(buffer, value, false);
    }

    fn encode_string(buffer: &mut Vec<u8>, s: &str, huffman: bool) {
        let bytes = s.as_bytes();
        let length = bytes.len();
        let prefix = if huffman { 0x80 } else { 0x00 };
        if length < 127 {
            buffer.push(prefix | length as u8);
        } else {
            buffer.push(prefix | 0x7F);
            Self::encode_int(buffer, length - 127);
        }
        
        buffer.extend_from_slice(bytes);
    }

    fn encode_int(buffer: &mut Vec<u8>, mut value: usize) {
        while value >= 128 {
            buffer.push(0x80 | (value & 0x7F) as u8);
            value >>= 7;
        }

        buffer.push(value as u8);
    }

    fn encode_prefix_int(buffer: &mut Vec<u8>, value: u64, prefix_bits: u8) {
        let max_prefix = (1u64 << prefix_bits) - 1;
        if value < max_prefix {
            buffer.push(value as u8);
        } else {
            buffer.push(max_prefix as u8);
            let mut remaining = value - max_prefix;
            while remaining >= 128 {
                buffer.push(0x80 | (remaining & 0x7F) as u8);
                remaining >>= 7;
            }

            buffer.push(remaining as u8);
        }
    }

    fn find_in_static_table(&self, name: &str, value: &str) -> Option<usize> {
        STATIC_TABLE.iter().position(|(n, v)| *n == name && *v == value)
    }

    fn find_name_in_static_table(&self, name: &str) -> Option<usize> {
        STATIC_TABLE.iter().position(|(n, _)| *n == name)
    }

    pub fn insert(&mut self, name: String, value: String) -> Result<()> {
        let entry = DynamicTableEntry::new(name, value);
        let entry_size = entry.size();
        if entry_size > self.max_table_capacity {
            return Err(Error::InvalidOperation(
                "Entry too large for table".to_string(),
            ));
        }
        
        while self.current_table_size + entry_size > self.max_table_capacity {
            if let Some(evicted) = self.dynamic_table.pop_back() {
                self.current_table_size -= evicted.size();
            } else {
                break;
            }
        }
        
        self.dynamic_table.push_front(entry);
        self.current_table_size += entry_size;
        self.insert_count += 1;
        
        Ok(())
    }

    pub fn set_capacity(&mut self, capacity: usize) -> Result<()> {
        self.max_table_capacity = capacity;
        while self.current_table_size > self.max_table_capacity {
            if let Some(evicted) = self.dynamic_table.pop_back() {
                self.current_table_size -= evicted.size();
            } else {
                break;
            }
        }
        
        Ok(())
    }
}

impl QpackDecoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            max_table_capacity,
            current_table_size: 0,
            insert_count: 0,
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>> {
        let mut cursor = 0;
        let mut headers = Vec::new();
        
        let (required_insert_count, consumed) = Self::decode_prefix_int(data, cursor, 8)?;
        cursor += consumed;
        
        let base = if required_insert_count > 0 {
            let (delta_base, consumed) = Self::decode_prefix_int(data, cursor, 7)?;
            cursor += consumed;
            
            let negative = (delta_base & 1) == 1;
            let delta = delta_base >> 1;
            if negative {
                required_insert_count - delta - 1
            } else {
                required_insert_count + delta
            }
        } else {
            0
        };

        let _ = base;

        while cursor < data.len() {
            let first_byte = data[cursor];
            if first_byte & 0xC0 == 0xC0 {
                let (index, consumed) = Self::decode_int(data, cursor, 6)?;
                cursor += consumed;
                
                let (name, value) = self.get_static_entry(index)?;
                headers.push((name.to_string(), value.to_string()));
            } else if first_byte & 0x80 == 0x80 {
                let (index, consumed) = Self::decode_int(data, cursor, 6)?;
                cursor += consumed;
                
                let (name, value) = self.get_dynamic_entry(index)?;
                headers.push((name, value));
            } else if first_byte & 0x50 == 0x50 {
                let (name_index, consumed) = Self::decode_int(data, cursor, 4)?;
                cursor += consumed;
                
                let (name, _) = self.get_static_entry(name_index)?;
                
                let (value, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;
                
                headers.push((name.to_string(), value));
            } else if first_byte & 0x40 == 0x40 {
                let (name_index, consumed) = Self::decode_int(data, cursor, 4)?;
                cursor += consumed;
                
                let (name, _) = self.get_dynamic_entry(name_index)?;
                
                let (value, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;
                
                headers.push((name, value));
            } else if first_byte & 0x20 == 0x20 {
                cursor += 1;
                
                let (name, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;
                
                let (value, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;
                
                headers.push((name, value));
            } else {
                return Err(Error::InvalidFrame);
            }
        }
        
        Ok(headers)
    }

    fn decode_int(data: &[u8], offset: usize, prefix_bits: u8) -> Result<(usize, usize)> {
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }
        
        let mask = (1u8 << prefix_bits) - 1;
        let mut value = (data[offset] & mask) as usize;
        if value < mask as usize {
            return Ok((value, 1));
        }
        
        let mut consumed = 1;
        let mut shift = 0;
        loop {
            if offset + consumed >= data.len() {
                return Err(Error::BufferTooShort);
            }
            
            let byte = data[offset + consumed];
            consumed += 1;
            
            value += ((byte & 0x7F) as usize) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        
        Ok((value, consumed))
    }

    fn decode_prefix_int(data: &[u8], offset: usize, prefix_bits: u8) -> Result<(u64, usize)> {
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }
        
        let mask = (1u8 << prefix_bits) - 1;
        let mut value = (data[offset] & mask) as u64;
        if value < mask as u64 {
            return Ok((value, 1));
        }
        
        let mut consumed = 1;
        let mut shift = 0;
        loop {
            if offset + consumed >= data.len() {
                return Err(Error::BufferTooShort);
            }
            
            let byte = data[offset + consumed];
            consumed += 1;
            
            value += ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        
        Ok((value, consumed))
    }

    fn decode_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }
        
        let first_byte = data[offset];
        let huffman = (first_byte & 0x80) != 0;
        
        let (length, mut consumed) = Self::decode_int(data, offset, 7)?;
        if offset + consumed + length > data.len() {
            return Err(Error::BufferTooShort);
        }
        
        let string_data = &data[offset + consumed..offset + consumed + length];
        consumed += length;
        
        let s = if huffman {
            return Err(Error::InvalidOperation(
                "Huffman encoding not yet supported".to_string(),
            ));
        } else {
            String::from_utf8(string_data.to_vec()).map_err(|_| Error::InvalidFrame)?
        };
        
        Ok((s, consumed))
    }

    fn get_static_entry(&self, index: usize) -> Result<(&str, &str)> {
        STATIC_TABLE.get(index).copied().ok_or(Error::InvalidFrame)
    }

    fn get_dynamic_entry(&self, index: usize) -> Result<(String, String)> {
        self.dynamic_table.get(index).map(|entry| (entry.name.clone(), entry.value.clone())).ok_or(Error::InvalidFrame)
    }

    pub fn insert(&mut self, name: String, value: String) -> Result<()> {
        let entry = DynamicTableEntry::new(name, value);
        let entry_size = entry.size();
        if entry_size > self.max_table_capacity {
            return Err(Error::InvalidOperation(
                "Entry too large for table".to_string(),
            ));
        }
        
        while self.current_table_size + entry_size > self.max_table_capacity {
            if let Some(evicted) = self.dynamic_table.pop_back() {
                self.current_table_size -= evicted.size();
            } else {
                break;
            }
        }
        
        self.dynamic_table.push_front(entry);
        self.current_table_size += entry_size;
        self.insert_count += 1;
        
        Ok(())
    }

    pub fn set_capacity(&mut self, capacity: usize) -> Result<()> {
        self.max_table_capacity = capacity;
        while self.current_table_size > self.max_table_capacity {
            if let Some(evicted) = self.dynamic_table.pop_back() {
                self.current_table_size -= evicted.size();
            } else {
                break;
            }
        }
        
        Ok(())
    }
}

pub fn select_secure_qpack_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_qpack_headers(headers: &[(String, String)], algorithm: CompressionAlgorithm) -> io::Result<(SecureQpackBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let mut encoder = QpackEncoder::new(4096);
    let raw_payload = encoder.encode(headers).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("qpack encode failed: {}", e)))?;
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure qpack nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_qpack_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let meta = SecureQpackBlobMeta {
        algorithm: selected_algorithm,
        nonce_b64: pem::encode(&nonce),
        digest_b64: pem::encode(&digest),
        tag_b64: pem::encode(&tag),
        raw_size: raw_payload.len(),
        encoded_size: encoded_payload.len(),
        issued_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = QPACK_BLOB_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        nonce = meta.nonce_b64,
        digest = meta.digest_b64,
        tag = meta.tag_b64,
        raw_size = meta.raw_size,
        encoded_size = meta.encoded_size,
        issued_at = meta.issued_at_unix,
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded_payload);

    Ok((meta, out))
}

pub fn encode_secure_qpack_headers_auto(headers: &[(String, String)], accept_encoding: &str) -> io::Result<(SecureQpackBlobMeta, Vec<u8>)> {
    encode_secure_qpack_headers(headers, select_secure_qpack_algorithm(accept_encoding))
}

pub fn decode_secure_qpack_headers(data: &[u8]) -> io::Result<(SecureQpackBlobMeta, Vec<(String, String)>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_qpack_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid qpack nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid qpack digest encoding: {}", e),
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid qpack tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || expected_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "qpack digest or tag has invalid length",
        ));
    }

    let computed_tag = compute_qpack_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure qpack blob tag verification failed",
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
                "qpack raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let computed_digest = sha256(&raw_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure qpack blob digest verification failed",
        ));
    }

    let mut decoder = QpackDecoder::new(4096);
    let headers = decoder.decode(&raw_payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("qpack decode failed: {}", e),
        )
    })?;

    Ok((meta, headers))
}

fn compute_qpack_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(QPACK_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(QPACK_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "qpack secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "qpack secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "qpack secure blob missing header/body separator",
    ))
}

fn parse_secure_qpack_meta(header: &str, body_len: usize) -> io::Result<SecureQpackBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != QPACK_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid qpack secure blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid qpack secure header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", v.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in qpack blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in qpack blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in qpack blob")
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureQpackBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in qpack secure blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in qpack secure blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in qpack secure blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in qpack secure blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in qpack secure blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in qpack secure blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "qpack encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_creation() {
        let encoder = QpackEncoder::new(4096);
        assert_eq!(encoder.max_table_capacity, 4096);
        assert_eq!(encoder.current_table_size, 0);
    }

    #[test]
    fn test_decoder_creation() {
        let decoder = QpackDecoder::new(4096);
        assert_eq!(decoder.max_table_capacity, 4096);
        assert_eq!(decoder.current_table_size, 0);
    }

    #[test]
    fn test_encode_simple_headers() {
        let mut encoder = QpackEncoder::new(4096);
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
        ];
        
        let encoded = encoder.encode(&headers).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut encoder = QpackEncoder::new(4096);
        let mut decoder = QpackDecoder::new(4096);
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/test".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];
        
        let encoded = encoder.encode(&headers).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();
        
        assert_eq!(headers.len(), decoded.len());
    }

    #[test]
    fn test_static_table_lookup() {
        let encoder = QpackEncoder::new(4096);
        
        let index = encoder.find_in_static_table(":method", "GET");
        assert!(index.is_some());
        
        let index = encoder.find_in_static_table(":path", "/");
        assert!(index.is_some());
    }

    #[test]
    fn test_dynamic_table_insertion() {
        let mut encoder = QpackEncoder::new(4096);
        
        encoder.insert("custom-header".to_string(), "custom-value".to_string()).unwrap();
        assert_eq!(encoder.dynamic_table.len(), 1);
        assert!(encoder.current_table_size > 0);
    }

    #[test]
    fn test_dynamic_table_eviction() {
        let mut encoder = QpackEncoder::new(100);
        
        encoder.insert("header1".to_string(), "value1".to_string()).unwrap();
        encoder.insert("header2".to_string(), "value2".to_string()).unwrap();
        encoder.insert("header3".to_string(), "value3".to_string()).unwrap();
        
        assert!(encoder.current_table_size <= encoder.max_table_capacity);
    }

    #[test]
    fn test_set_capacity() {
        let mut encoder = QpackEncoder::new(4096);
        
        encoder.insert("header1".to_string(), "value1".to_string()).unwrap();
        encoder.insert("header2".to_string(), "value2".to_string()).unwrap();
        
        encoder.set_capacity(50).unwrap();
        assert!(encoder.current_table_size <= 50);
    }

    #[test]
    fn test_encode_literal_field() {
        let mut encoder = QpackEncoder::new(4096);
        
        let headers = vec![
            ("custom-header".to_string(), "custom-value".to_string()),
        ];
        
        let encoded = encoder.encode(&headers).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_integer_encoding() {
        let mut buffer = Vec::new();
        
        QpackEncoder::encode_int(&mut buffer, 127);
        assert!(!buffer.is_empty());
        
        buffer.clear();
        QpackEncoder::encode_int(&mut buffer, 128);
        assert_eq!(buffer.len(), 2);
        
        buffer.clear();
        QpackEncoder::encode_int(&mut buffer, 16383);
        assert!(buffer.len() > 1);
    }

    #[test]
    fn test_string_encoding() {
        let mut buffer = Vec::new();
        
        QpackEncoder::encode_string(&mut buffer, "test", false);
        assert!(!buffer.is_empty());
        assert_eq!(buffer[0] & 0x80, 0);
    }

    #[test]
    fn test_prefix_int_encoding() {
        let mut buffer = Vec::new();
        
        QpackEncoder::encode_prefix_int(&mut buffer, 10, 5);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer[0], 10);
        
        buffer.clear();
        QpackEncoder::encode_prefix_int(&mut buffer, 100, 5);
        assert!(buffer.len() > 1);
    }

    #[test]
    fn test_secure_qpack_roundtrip_identity() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];

        let (meta, blob) =
            encode_secure_qpack_headers(&headers, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_headers) = decode_secure_qpack_headers(&blob).unwrap();
        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(decoded_headers.len(), headers.len());
    }

    #[test]
    fn test_secure_qpack_roundtrip_compressed() {
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/upload".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept-encoding".to_string(), "gzip, br".to_string()),
        ];

        let (_meta, blob) =
            encode_secure_qpack_headers(&headers, CompressionAlgorithm::Gzip).unwrap();

        let (_decoded_meta, decoded_headers) = decode_secure_qpack_headers(&blob).unwrap();
        assert_eq!(decoded_headers.len(), headers.len());
    }

    #[test]
    fn test_secure_qpack_tamper_detected() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/tamper".to_string()),
        ];

        let (_meta, mut blob) =
            encode_secure_qpack_headers(&headers, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len().checked_sub(1).unwrap();
        blob[idx] ^= 0x01;

        let result = decode_secure_qpack_headers(&blob);
        assert!(result.is_err());
    }
}