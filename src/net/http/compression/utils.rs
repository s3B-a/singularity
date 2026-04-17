use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const CRC32_TABLE: [u32; 256] = generate_crc32_table();

const COMPRESSION_UTIL_BLOB_MAGIC: &str = "SINGULARITY_HTTP_COMPRESSION_UTIL_BLOB_V1";
const COMPRESSION_UTIL_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_COMPRESSION_UTIL_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCompressionUtilBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xedb88320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }

            j += 1;
        }

        table[i] = crc;
        i += 1;
    }
    
    table
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffffffff;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xff) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }

    crc ^ 0xffffffff
}

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc ^ 0xffffffff;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xff) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }

    crc ^ 0xffffffff
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

pub fn adler32_update(adler: u32, data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a = (adler & 0xffff) as u32;
    let mut b = (adler >> 16) as u32;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

pub fn bytes_needed(value: u64) -> usize {
    if value == 0 {
        return 1;
    }

    let mut bytes = 0;
    let mut v = value;
    while v > 0 {
        bytes += 1;
        v >>= 8;
    }

    bytes
}

pub fn reverse_bits(byte: u8) -> u8 {
    let mut result = 0u8;
    let mut b = byte;
    for _ in 0..8 {
        result = (result << 1) | (b & 1);
        b >>= 1;
    }

    result
}

pub fn reverse_bits_u16(value: u16, num_bits: u8) -> u16 {
    let mut result = 0u16;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }

    result
}

pub struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    pub fn read_bits(&mut self, n: u8) -> Option<u32> {
        if n > 32 {
            return None;
        }

        let mut result = 0u32;
        let mut bits_read = 0u8;
        while bits_read < n {
            if self.byte_pos >= self.data.len() {
                return None;
            }

            let bits_available = 8 - self.bit_pos;
            let bits_to_read = (n - bits_read).min(bits_available);
            let byte = self.data[self.byte_pos];
            let shift = bits_available - bits_to_read;
            let mask = if bits_to_read == 8 {
                0xffu32
            } else {
                (1u32 << bits_to_read) - 1
            };

            let bits = (byte as u32 >> shift) & mask;
            result = (result << bits_to_read) | bits;
            bits_read += bits_to_read;
            self.bit_pos += bits_to_read;

            if self.bit_pos >= 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }

        Some(result)
    }

    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    pub fn position(&self) -> usize {
        self.byte_pos
    }

    pub fn has_more(&self) -> bool {
        self.byte_pos < self.data.len()
    }

    pub fn peek_bits(&self, n: u8) -> Option<u32> {
        let mut temp = self.clone();
        temp.read_bits(n)
    }
}

pub struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    pub fn write_bits(&mut self, value: u32, n: u8) {
        if n == 0 || n > 32 {
            return;
        }

        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte = (self.current_byte << 1) | bit;
            self.bit_pos += 1;
            if self.bit_pos >= 8 {
                self.data.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    pub fn write_bits_reverse(&mut self, value: u32, n: u8) {
        for i in 0..n {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte = (self.current_byte << 1) | bit;
            self.bit_pos += 1;
            if self.bit_pos >= 8 {
                self.data.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.current_byte <<= 8 - self.bit_pos;
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.bit_pos != 0 {
            self.current_byte <<= 8 - self.bit_pos;
            self.data.push(self.current_byte);
        }
        
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len() + if self.bit_pos > 0 { 1 } else { 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.bit_pos == 0
    }
}

pub struct SlidingWindow {
    buffer: Vec<u8>,
    size: usize,
    pub pos: usize,
}

impl SlidingWindow {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            size,
            pos: 0,
        }
    }

    pub fn push(&mut self, byte: u8) {
        self.buffer[self.pos] = byte;
        self.pos = (self.pos + 1) % self.size;
    }

    pub fn push_slice(&mut self, data: &[u8]) {
        for &byte in data {
            self.push(byte);
        }
    }

    pub fn get(&self, offset: usize) -> Option<u8> {
        if offset > self.size || offset == 0 {
            return None;
        }

        let idx = (self.pos + self.size - offset) % self.size;
        Some(self.buffer[idx])
    }

    pub fn find_match(&self, data: &[u8], max_length: usize) -> Option<(usize, usize)> {
        if data.is_empty() || max_length == 0 {
            return None;
        }

        let mut best_match: Option<(usize, usize)> = None;
        let max_length = max_length.min(data.len()).min(258);
        for offset in 1..=self.size.min(self.pos) {
            let idx = (self.pos + self.size - offset) % self.size;
            let mut match_len = 0;
            while match_len < max_length && match_len < data.len() {
                let window_byte = self.buffer[(idx + match_len) % self.size];
                let data_byte = data[match_len];
                if window_byte != data_byte {
                    break;
                }

                match_len += 1;
            }
            
            if match_len > 0 {
                if let Some((_, best_len)) = best_match {
                    if match_len > best_len {
                        best_match = Some((offset, match_len));
                    }
                } else {
                    best_match = Some((offset, match_len));
                }
            }
        }

        best_match
    }

    pub fn clear(&mut self) {
        self.buffer.fill(0);
        self.pos = 0;
    }
}

pub fn select_secure_compression_util_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    super::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_compression_util_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureCompressionUtilBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = data.to_vec();
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        super::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate compression util nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_compression_util_blob_tag(
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
        magic = COMPRESSION_UTIL_BLOB_MAGIC,
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
        SecureCompressionUtilBlobMeta {
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

pub fn encode_secure_compression_util_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureCompressionUtilBlobMeta, Vec<u8>)> {
    let selected = select_secure_compression_util_algorithm(accept_encoding);
    encode_secure_compression_util_payload(data, selected)
}

pub fn decode_secure_compression_util_payload(data: &[u8]) -> io::Result<(SecureCompressionUtilBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_compression_util_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression util nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression util digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid compression util tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression util digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_compression_util_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression util blob HMAC mismatch",
        ));
    }

    let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        super::decompress(meta.algorithm, body)?
    };

    if raw_payload.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compression util raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compression util blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

fn compute_compression_util_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(COMPRESSION_UTIL_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(COMPRESSION_UTIL_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "compression util header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "compression util header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "compression util blob missing header/body separator",
    ))
}

fn parse_secure_compression_util_blob_meta(header: &str, body_len: usize) -> io::Result<SecureCompressionUtilBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != COMPRESSION_UTIL_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid compression util blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid compression util header line '{}'", line),
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
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in compression util blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in compression util blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in compression util blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in compression util blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in compression util blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in compression util blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compression util encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureCompressionUtilBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl<'a> Clone for BitReader<'a> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            byte_pos: self.byte_pos,
            bit_pos: self.bit_pos,
        }
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0);
    }

    #[test]
    fn test_crc32_known_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
    }

    #[test]
    fn test_crc32_update() {
        let data = b"Hello, World!";
        let crc1 = crc32(data);
        
        let crc_part1 = crc32_update(0, &data[..5]);
        let crc_part2 = crc32_update(crc_part1, &data[5..]);
        
        assert_eq!(crc1, crc_part2);
    }

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn test_adler32_known_values() {
        let result = adler32(b"Wikipedia");
        assert!(result > 0);
    }

    #[test]
    fn test_adler32_update() {
        let data = b"Hello, World!";
        let adler1 = adler32(data);
        
        let adler_part1 = adler32_update(1, &data[..5]);
        let adler_part2 = adler32_update(adler_part1, &data[5..]);
        
        assert_eq!(adler1, adler_part2);
    }

    #[test]
    fn test_bit_reader_basic() {
        let data = vec![0b10110010];
        let mut reader = BitReader::new(&data);
        
        assert_eq!(reader.read_bits(2), Some(0b10));
        assert_eq!(reader.read_bits(3), Some(0b110));
        assert_eq!(reader.read_bits(3), Some(0b010));
    }

    #[test]
    fn test_bit_reader_align() {
        let data = vec![0b10110010, 0b11001101];
        let mut reader = BitReader::new(&data);
        
        reader.read_bits(3).unwrap();
        reader.align_to_byte();
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn test_bit_writer_basic() {
        let mut writer = BitWriter::new();
        
        writer.write_bits(0b10, 2);
        writer.write_bits(0b110, 3);
        writer.write_bits(0b010, 3);
        
        let result = writer.finish();
        assert_eq!(result[0], 0b10110010);
    }

    #[test]
    fn test_bit_writer_align() {
        let mut writer = BitWriter::new();
        
        writer.write_bits(0b101, 3);
        writer.align_to_byte();
        
        let result = writer.finish();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0b10100000);
    }

    #[test]
    fn test_bit_roundtrip() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b1010, 4);
        writer.write_bits(0b110011, 6);
        writer.write_bits(0b11, 2);
        
        let data = writer.finish();
        let mut reader = BitReader::new(&data);
        
        assert_eq!(reader.read_bits(4), Some(0b1010));
        assert_eq!(reader.read_bits(6), Some(0b110011));
        assert_eq!(reader.read_bits(2), Some(0b11));
    }

    #[test]
    fn test_sliding_window_basic() {
        let mut window = SlidingWindow::new(8);
        
        window.push(1);
        window.push(2);
        window.push(3);
        
        assert_eq!(window.get(0), None);
        assert_eq!(window.get(1), Some(3));
        assert_eq!(window.get(2), Some(2));
        assert_eq!(window.get(3), Some(1));
    }

    #[test]
    fn test_sliding_window_wrap() {
        let mut window = SlidingWindow::new(4);
        
        for i in 0..10 {
            window.push(i);
        }
        
        assert_eq!(window.get(1), Some(9));
        assert_eq!(window.get(2), Some(8));
        assert_eq!(window.get(3), Some(7));
        assert_eq!(window.get(4), Some(6));
    }

    #[test]
    fn test_sliding_window_find_match() {
        let mut window = SlidingWindow::new(32);
        let pattern = b"HELLO";
        
        window.push_slice(pattern);
        window.push_slice(b" WORLD ");
        
        let search = b"HEL";
        let result = window.find_match(search, 10);
        
        assert!(result.is_some(), "Expected to find a match for 'HEL'");
        if let Some((offset, length)) = result {
            assert!(length >= 3, "Expected match length >= 3, got {}", length);
            assert!(offset > 0, "Expected positive offset");
        }
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b10110010), 0b01001101);
        assert_eq!(reverse_bits(0b00000001), 0b10000000);
        assert_eq!(reverse_bits(0b11111111), 0b11111111);
    }

    #[test]
    fn test_reverse_bits_u16() {
        assert_eq!(reverse_bits_u16(0b101, 3), 0b101);
        assert_eq!(reverse_bits_u16(0b110, 3), 0b011);
        assert_eq!(reverse_bits_u16(0b1010, 4), 0b0101);
    }

    #[test]
    fn test_bytes_needed() {
        assert_eq!(bytes_needed(0), 1);
        assert_eq!(bytes_needed(255), 1);
        assert_eq!(bytes_needed(256), 2);
        assert_eq!(bytes_needed(65535), 2);
        assert_eq!(bytes_needed(65536), 3);
    }

    #[test]
    fn test_bit_reader_peek() {
        let data = vec![0b10110010];
        let reader = BitReader::new(&data);
        
        assert_eq!(reader.peek_bits(2), Some(0b10));
        assert_eq!(reader.peek_bits(2), Some(0b10));
    }

    #[test]
    fn test_secure_compression_util_blob_roundtrip_identity() {
        let payload = b"compression utils secure payload identity".to_vec();
        let (meta, blob) =
            encode_secure_compression_util_payload(&payload, CompressionAlgorithm::Identity)
                .unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_compression_util_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_compression_util_blob_roundtrip_gzip() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let (meta, blob) =
            encode_secure_compression_util_payload(&payload, CompressionAlgorithm::Gzip).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, restored) = decode_secure_compression_util_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_compression_util_blob_tamper_detection() {
        let payload = b"tamper".to_vec();
        let (_, mut blob) =
            encode_secure_compression_util_payload(&payload, CompressionAlgorithm::Identity)
                .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_compression_util_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}