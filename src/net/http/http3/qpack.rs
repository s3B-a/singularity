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
    abs_index: u64,
}

#[derive(Debug)]
pub struct QpackEncoder {
    dynamic_table: VecDeque<DynamicTableEntry>,
    max_table_capacity: usize,
    current_table_size: usize,
    insert_count: u64,
    pending_instructions: Vec<u8>,
    known_received_count: u64,
}

#[derive(Debug)]
pub struct QpackDecoder {
    dynamic_table: VecDeque<DynamicTableEntry>,
    max_table_capacity: usize,
    current_table_size: usize,
    insert_count: u64,
    pending_instructions: Vec<u8>,
}

impl DynamicTableEntry {
    fn new(name: String, value: String, abs_index: u64) -> Self {
        let size = 32 + name.len() + value.len();
        Self { name, value, size, abs_index }
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
            pending_instructions: Vec::new(),
            known_received_count: 0,
        }
    }

    pub fn encode(&mut self, headers: &[(String, String)]) -> Result<Vec<u8>> {
        enum FieldOp {
            Indexed { abs_index: u64, dynamic: bool },
            LiteralWithNameRef { name_index: usize, dynamic: bool, value: String },
            Literal { name: String, value: String },
        }

        let mut ops = Vec::with_capacity(headers.len());
        let mut used_dynamic = false;

        for (name, value) in headers {
            if let Some(static_idx) = self.find_in_static_table(name, value) {
                ops.push(FieldOp::Indexed { abs_index: static_idx as u64, dynamic: false });
            } else if let Some(dyn_abs) = self.find_in_dynamic_table(name, value) {
                ops.push(FieldOp::Indexed { abs_index: dyn_abs, dynamic: true });
                used_dynamic = true;
            } else if let Some(static_name_idx) = self.find_name_in_static_table(name) {
                if self.try_insert(name.clone(), value.clone()) {
                    Self::encode_insert_with_name_ref(&mut self.pending_instructions, static_name_idx as u64, true, value);
                    ops.push(FieldOp::Indexed { abs_index: self.insert_count - 1, dynamic: true });
                    used_dynamic = true;
                } else {
                    ops.push(FieldOp::LiteralWithNameRef { name_index: static_name_idx, dynamic: false, value: value.clone() });
                }
            } else if let Some(dyn_name_abs) = self.find_name_in_dynamic_table(name) {
                ops.push(FieldOp::LiteralWithNameRef { name_index: dyn_name_abs as usize, dynamic: true, value: value.clone() });
                used_dynamic = true;
            } else if self.try_insert(name.clone(), value.clone()) {
                Self::encode_insert_with_literal_name(&mut self.pending_instructions, name, value);
                ops.push(FieldOp::Indexed { abs_index: self.insert_count - 1, dynamic: true });
                used_dynamic = true;
            } else {
                ops.push(FieldOp::Literal { name: name.clone(), value: value.clone() });
            }
        }

        let base = self.insert_count;
        let required_insert_count = if used_dynamic { base } else { 0 };

        let mut encoded = Vec::new();
        Self::encode_prefix_int(&mut encoded, required_insert_count, 8);
        if required_insert_count > 0 {
            Self::encode_prefix_int(&mut encoded, 0, 7);
        }

        for op in ops {
            match op {
                FieldOp::Indexed { abs_index, dynamic } => {
                    let index = if dynamic { (base - 1 - abs_index) as usize } else { abs_index as usize };
                    Self::encode_indexed_field_line(&mut encoded, index, dynamic);
                }
                FieldOp::LiteralWithNameRef { name_index, dynamic, value } => {
                    let index = if dynamic { (base - 1 - name_index as u64) as usize } else { name_index };
                    Self::encode_literal_with_name_ref(&mut encoded, index, &value, dynamic, false);
                }
                FieldOp::Literal { name, value } => {
                    Self::encode_literal_field_line(&mut encoded, &name, &value, false);
                }
            }
        }

        Ok(encoded)
    }

    pub fn drain_instructions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_instructions)
    }

    pub fn set_capacity_and_announce(&mut self, capacity: usize) -> Result<()> {
        self.set_capacity(capacity)?;
        Self::encode_set_capacity(&mut self.pending_instructions, capacity as u64);
        Ok(())
    }

    pub fn process_decoder_instructions(&mut self, data: &[u8]) -> Result<usize> {
        let mut cursor = 0;
        while cursor < data.len() {
            let first_byte = data[cursor];
            if first_byte & 0x80 == 0x80 {
                let (_stream_id, consumed) = QpackDecoder::decode_int(data, cursor, 7)?;
                cursor += consumed;
            } else if first_byte & 0x40 == 0x40 {
                let (_stream_id, consumed) = QpackDecoder::decode_int(data, cursor, 6)?;
                cursor += consumed;
            } else {
                let (increment, consumed) = QpackDecoder::decode_int(data, cursor, 6)?;
                cursor += consumed;
                self.known_received_count = self.known_received_count.saturating_add(increment as u64);
            }
        }

        Ok(cursor)
    }

    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    fn encode_insert_with_name_ref(buffer: &mut Vec<u8>, name_index: u64, static_table: bool, value: &str) {
        let prefix = 0x80 | if static_table { 0x40 } else { 0x00 };
        let prefix_bits = 6u64;
        let max = (1u64 << prefix_bits) - 1;
        if name_index < max {
            buffer.push(prefix | name_index as u8);
        } else {
            buffer.push(prefix | max as u8);
            Self::encode_int(buffer, (name_index - max) as usize);
        }

        Self::encode_string(buffer, value, false);
    }

    fn encode_insert_with_literal_name(buffer: &mut Vec<u8>, name: &str, value: &str) {
        let bytes = name.as_bytes();
        let length = bytes.len();
        let prefix = 0x40;
        if length < 31 {
            buffer.push(prefix | length as u8);
        } else {
            buffer.push(prefix | 0x1F);
            Self::encode_int(buffer, length - 31);
        }

        buffer.extend_from_slice(bytes);
        Self::encode_string(buffer, value, false);
    }

    fn encode_set_capacity(buffer: &mut Vec<u8>, capacity: u64) {
        let prefix_bits = 5u64;
        let max = (1u64 << prefix_bits) - 1;
        if capacity < max {
            buffer.push(0x20 | capacity as u8);
        } else {
            buffer.push(0x20 | max as u8);
            Self::encode_int(buffer, (capacity - max) as usize);
        }
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

    fn find_in_dynamic_table(&self, name: &str, value: &str) -> Option<u64> {
        self.dynamic_table.iter().find(|e| e.name == name && e.value == value).map(|e| e.abs_index)
    }

    fn find_name_in_dynamic_table(&self, name: &str) -> Option<u64> {
        self.dynamic_table.iter().find(|e| e.name == name).map(|e| e.abs_index)
    }

    fn try_insert(&mut self, name: String, value: String) -> bool {
        let entry_size = 32 + name.len() + value.len();
        if entry_size > self.max_table_capacity {
            return false;
        }

        self.insert(name, value).is_ok()
    }

    pub fn insert(&mut self, name: String, value: String) -> Result<()> {
        let abs_index = self.insert_count;
        let entry = DynamicTableEntry::new(name, value, abs_index);
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
            pending_instructions: Vec::new(),
        }
    }

    pub fn process_encoder_instructions(&mut self, data: &[u8]) -> Result<usize> {
        let mut cursor = 0;
        let mut inserted = 0u64;

        while cursor < data.len() {
            let first_byte = data[cursor];
            if first_byte & 0x80 == 0x80 {
                let static_table = (first_byte & 0x40) != 0;
                let (name_index, consumed) = Self::decode_int(data, cursor, 6)?;
                cursor += consumed;

                let name = if static_table {
                    self.get_static_entry(name_index)?.0.to_string()
                } else {
                    self.get_dynamic_entry(name_index)?.0
                };

                let (value, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;

                self.insert(name, value)?;
                inserted += 1;
            } else if first_byte & 0x40 == 0x40 {
                let (name, consumed) = Self::decode_literal_name_string(data, cursor)?;
                cursor += consumed;

                let (value, consumed) = Self::decode_string(data, cursor)?;
                cursor += consumed;

                self.insert(name, value)?;
                inserted += 1;
            } else if first_byte & 0x20 == 0x20 {
                let (capacity, consumed) = Self::decode_int(data, cursor, 5)?;
                cursor += consumed;
                self.set_capacity(capacity)?;
            } else {
                return Err(Error::InvalidFrame);
            }
        }

        if inserted > 0 {
            Self::encode_insert_count_increment(&mut self.pending_instructions, inserted);
        }

        Ok(cursor)
    }

    pub fn acknowledge_section(&mut self, stream_id: u64) {
        let prefix_bits = 7u64;
        let max = (1u64 << prefix_bits) - 1;
        if stream_id < max {
            self.pending_instructions.push(0x80 | stream_id as u8);
        } else {
            self.pending_instructions.push(0x80 | max as u8);
            QpackEncoder::encode_int(&mut self.pending_instructions, (stream_id - max) as usize);
        }
    }

    pub fn drain_instructions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_instructions)
    }

    fn encode_insert_count_increment(buffer: &mut Vec<u8>, increment: u64) {
        let prefix_bits = 6u64;
        let max = (1u64 << prefix_bits) - 1;
        if increment < max {
            buffer.push(increment as u8);
        } else {
            buffer.push(max as u8);
            QpackEncoder::encode_int(buffer, (increment - max) as usize);
        }
    }

    fn decode_literal_name_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let first_byte = data[offset];
        let huffman = (first_byte & 0x20) != 0;

        let (length, mut consumed) = Self::decode_int(data, offset, 5)?;
        if offset + consumed + length > data.len() {
            return Err(Error::BufferTooShort);
        }

        let name_data = &data[offset + consumed..offset + consumed + length];
        consumed += length;

        if huffman {
            return Err(Error::InvalidOperation(
                "Huffman encoding not yet supported".to_string(),
            ));
        }

        let name = String::from_utf8(name_data.to_vec()).map_err(|_| Error::InvalidFrame)?;
        Ok((name, consumed))
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
        
        let mask = ((1u16 << prefix_bits) - 1) as u8;
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

        let mask = ((1u16 << prefix_bits) - 1) as u8;
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
        let abs_index = self.insert_count;
        let entry = DynamicTableEntry::new(name, value, abs_index);
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

    let mut encoder = QpackEncoder::new(0);
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

        let instructions = encoder.drain_instructions();
        assert!(!instructions.is_empty(), "some headers should have been added to the dynamic table");
        decoder.process_encoder_instructions(&instructions).unwrap();

        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(headers.len(), decoded.len());
        assert_eq!(decoded, headers);
    }

    #[test]
    fn test_encode_reuses_dynamic_table_on_repeat_header() {
        let mut encoder = QpackEncoder::new(4096);
        let mut decoder = QpackDecoder::new(4096);

        let headers = vec![(":authority".to_string(), "example.com".to_string())];

        let first_encoded = encoder.encode(&headers).unwrap();
        decoder.process_encoder_instructions(&encoder.drain_instructions()).unwrap();
        assert_eq!(decoder.decode(&first_encoded).unwrap(), headers);

        let second_encoded = encoder.encode(&headers).unwrap();
        assert!(encoder.drain_instructions().is_empty());
        assert_eq!(decoder.decode(&second_encoded).unwrap(), headers);
    }

    #[test]
    fn test_decoder_generates_insert_count_increment() {
        let mut encoder = QpackEncoder::new(4096);
        let mut decoder = QpackDecoder::new(4096);

        let headers = vec![("x-custom".to_string(), "value".to_string())];
        encoder.encode(&headers).unwrap();
        let instructions = encoder.drain_instructions();
        assert!(!instructions.is_empty());

        decoder.process_encoder_instructions(&instructions).unwrap();
        let decoder_instructions = decoder.drain_instructions();
        assert!(!decoder_instructions.is_empty(), "an Insert Count Increment should have been queued");

        encoder.process_decoder_instructions(&decoder_instructions).unwrap();
        assert_eq!(encoder.known_received_count(), 1);
    }

    #[test]
    fn test_set_capacity_and_announce_roundtrips_through_decoder() {
        let mut encoder = QpackEncoder::new(4096);
        let mut decoder = QpackDecoder::new(4096);

        encoder.set_capacity_and_announce(8192).unwrap();
        let instructions = encoder.drain_instructions();
        assert!(!instructions.is_empty());

        decoder.process_encoder_instructions(&instructions).unwrap();
        assert_eq!(decoder.max_table_capacity, 8192);
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