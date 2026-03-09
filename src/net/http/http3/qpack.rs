use super::error::{Error, Result};
use std::collections::VecDeque;

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
        let prefix_bits = if dynamic { 6 } else { 6 };
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
            return Err(Error::InvalidOperation("Entry too large for table".to_string()));
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
            return Err(Error::InvalidOperation("Huffman encoding not yet supported".to_string()));
        } else {
            String::from_utf8(string_data.to_vec())
                .map_err(|_| Error::InvalidFrame)?
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
            return Err(Error::InvalidOperation("Entry too large for table".to_string()));
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
}