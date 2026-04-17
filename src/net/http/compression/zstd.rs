use super::utils::SlidingWindow;
use super::{CompressionAlgorithm, CompressionLevel, Compressor, Decompressor};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const ZSTD_MAGIC: u32 = 0x28B52FFD;
const ZSTD_MIN_WINDOW_SIZE: u32 = 1024;
const ZSTD_MAX_WINDOW_SIZE: u32 = 1 << 31;
const ZSTD_DEFAULT_BLOCK_SIZE: usize = 128 * 1024;
const ZSTD_MIN_MATCH_LENGTH: usize = 3;
const ZSTD_MAX_MATCH_LENGTH: usize = 131072;

const ZSTD_BLOB_MAGIC: &str = "SINGULARITY_HTTP_ZSTD_BLOB_V1";
const ZSTD_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_ZSTD_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureZstdBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    checksum_flag: bool,
    unused_flag: bool,
    single_segment_flag: bool,
    content_size_flag: bool,
    content_checksum_flag: bool,
    reserved_flag: bool,
    version: u8,
    window_size: u32,
    content_size: Option<u64>,
    dictionary_id: Option<u32>,
}

impl FrameHeader {
    #[inline]
    fn content_size_len(size: u64) -> usize {
        if size <= 0xFF {
            1
        } else if size <= 0xFFFF {
            2
        } else if size <= 0xFFFF_FFFF {
            4
        } else {
            8
        }
    }

    #[inline]
    fn len_to_code(len: usize) -> u8 {
        match len {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        }
    }

    #[inline]
    fn code_to_len(code: u8) -> usize {
        match code & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        }
    }

    fn parse(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Frame header is empty"));
        }

        let descriptor = data[0];
        let mut offset = 1;
        let content_size_len_code = descriptor & 0x03;
        let checksum_flag = (descriptor & 0x04) != 0;
        let unused_flag = (descriptor & 0x08) != 0;
        let reserved_flag = (descriptor & 0x10) != 0;
        let single_segment_flag = (descriptor & 0x20) != 0;
        let content_size_flag = (descriptor & 0x40) != 0;
        let content_checksum_flag = (descriptor & 0x80) != 0;

        let window_size = if !single_segment_flag {
            if offset >= data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "EOF reading window size"));
            }

            let window_byte = data[offset];
            offset += 1;

            let exponent = (window_byte >> 3) & 0x1F;
            let mantissa = window_byte & 0x07;
            (1u32 << (10 + exponent)) + ((mantissa as u32) << (7 + exponent))
        } else {
            0
        };

        let content_size = if content_size_flag {
            let size_len = Self::code_to_len(content_size_len_code);
            if offset + size_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "EOF reading content size"));
            }

            let mut size = 0u64;
            for i in 0..size_len {
                size |= (data[offset + i] as u64) << (8 * i);
            }
            offset += size_len;
            Some(size)
        } else {
            None
        };

        let dictionary_id = if unused_flag {
            if offset + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "EOF reading dictionary ID"));
            }

            let id = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            Some(id)
        } else {
            None
        };

        Ok((
            FrameHeader {
                checksum_flag,
                unused_flag,
                single_segment_flag,
                content_size_flag,
                content_checksum_flag,
                reserved_flag,
                version: 0,
                window_size,
                content_size,
                dictionary_id,
            },
            offset,
        ))
    }

    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        let content_size_len = if self.content_size_flag {
            Self::content_size_len(self.content_size.unwrap_or(0))
        } else {
            1
        };
        let mut descriptor = Self::len_to_code(content_size_len);

        if self.checksum_flag {
            descriptor |= 0x04;
        }
        if self.unused_flag {
            descriptor |= 0x08;
        }
        if self.reserved_flag {
            descriptor |= 0x10;
        }
        if self.single_segment_flag {
            descriptor |= 0x20;
        }
        if self.content_size_flag {
            descriptor |= 0x40;
        }
        if self.content_checksum_flag {
            descriptor |= 0x80;
        }

        data.push(descriptor);

        if !self.single_segment_flag {
            let window_size = self.window_size.clamp(ZSTD_MIN_WINDOW_SIZE, ZSTD_MAX_WINDOW_SIZE);
            let bits = 32 - window_size.leading_zeros();
            let exponent = (bits.saturating_sub(10)).min(31) as u8;
            let base = 1u32 << (10 + exponent);
            let mantissa = ((window_size.saturating_sub(base)) >> (7 + exponent)) & 0x7;
            data.push(((exponent & 0x1F) << 3) | (mantissa as u8));
        }

        if self.content_size_flag {
            let size = self.content_size.unwrap_or(0);
            let le = size.to_le_bytes();
            data.extend_from_slice(&le[..content_size_len]);
        }

        if self.unused_flag {
            data.extend_from_slice(&self.dictionary_id.unwrap_or(0).to_le_bytes());
        }

        data
    }
}

pub struct ZstdCompressor {
    level: CompressionLevel,
    window: SlidingWindow,
}

impl ZstdCompressor {
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            level,
            window: SlidingWindow::new(ZSTD_MAX_WINDOW_SIZE as usize),
        }
    }

    fn compress_block(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let block_size = std::cmp::min(ZSTD_DEFAULT_BLOCK_SIZE, data.len() - pos);
            let block_data = &data[pos..pos + block_size];
            let last_block = (pos + block_size) >= data.len();
            let block_type = 0u32;
            let size_minus_1 = (block_size.saturating_sub(1)) as u32;
            let mut header = 0u32;
            if last_block {
                header |= 1;
            }

            header |= (block_type & 0x3) << 1;
            header |= (size_minus_1 & 0x1FFFFF) << 3;

            output.push((header & 0xFF) as u8);
            output.push(((header >> 8) & 0xFF) as u8);
            output.push(((header >> 16) & 0xFF) as u8);

            output.extend_from_slice(block_data);
            self.window.push_slice(block_data);

            pos += block_size;
        }

        Ok(output)
    }
}

pub struct ZstdDecompressor {
    window: SlidingWindow,
}

impl ZstdDecompressor {
    pub fn new() -> Self {
        Self {
            window: SlidingWindow::new(ZSTD_MAX_WINDOW_SIZE as usize),
        }
    }

    fn decompress_blocks(&mut self, data: &[u8], mut offset: usize) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut last_block = false;
        while offset < data.len() && !last_block {
            if offset + 3 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Block header truncated"));
            }

            let header_byte1 = data[offset] as u32;
            let header_byte2 = data[offset + 1] as u32;
            let header_byte3 = data[offset + 2] as u32;
            let header = header_byte1 | (header_byte2 << 8) | (header_byte3 << 16);
            offset += 3;

            last_block = (header & 1) != 0;
            let block_type = (header >> 1) & 0x3;
            let block_size = (((header >> 3) & 0x1FFFFF) + 1) as usize;
            if offset + block_size > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Block data truncated: need {} bytes at offset {}, have {} total bytes",
                        block_size, offset, data.len()
                    ),
                ));
            }

            match block_type {
                0 => {
                    output.extend_from_slice(&data[offset..offset + block_size]);
                    self.window.push_slice(&data[offset..offset + block_size]);
                }
                1 => {
                    if block_size > 0 {
                        let byte = data[offset];
                        for _ in 0..block_size {
                            output.push(byte);
                            self.window.push(byte);
                        }
                    }
                }
                2 => {
                    output.extend_from_slice(&data[offset..offset + block_size]);
                    self.window.push_slice(&data[offset..offset + block_size]);
                }
                3 => {
                    output.extend_from_slice(&data[offset..offset + block_size]);
                    self.window.push_slice(&data[offset..offset + block_size]);
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid block type"));
                }
            }

            offset += block_size;
        }

        Ok(output)
    }
}

pub fn select_secure_zstd_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = super::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in &parsed {
        if *quality > 0.0 && *algorithm == CompressionAlgorithm::Zstd && algorithm.is_implemented() {
            return *algorithm;
        }
    }

    parsed.into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_zstd_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureZstdBlobMeta, Vec<u8>)> {
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
            format!("failed to generate zstd blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_zstd_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = ZSTD_BLOB_MAGIC,
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
        SecureZstdBlobMeta {
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

pub fn encode_secure_zstd_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureZstdBlobMeta, Vec<u8>)> {
    let selected = select_secure_zstd_algorithm(accept_encoding);
    encode_secure_zstd_payload(data, selected)
}

pub fn decode_secure_zstd_payload(data: &[u8]) -> io::Result<(SecureZstdBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_zstd_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid zstd nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid zstd digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid zstd tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zstd digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_zstd_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zstd blob HMAC mismatch",
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
                "zstd raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zstd blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

pub fn compress(data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    let mut compressor = ZstdCompressor::new(level);
    compressor.compress(data)
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decompressor = ZstdDecompressor::new();
    decompressor.decompress(data)
}

impl Compressor for ZstdCompressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.window.clear();
        let _ = self.level;
        let _ = ZSTD_MIN_MATCH_LENGTH;
        let _ = ZSTD_MAX_MATCH_LENGTH;
        let mut output = Vec::new();
        output.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
        let frame_header = FrameHeader {
            checksum_flag: false,
            unused_flag: false,
            single_segment_flag: input.len() < 256 * 1024,
            content_size_flag: true,
            content_checksum_flag: false,
            reserved_flag: false,
            version: 0,
            window_size: ZSTD_DEFAULT_BLOCK_SIZE as u32,
            content_size: Some(input.len() as u64),
            dictionary_id: None,
        };

        output.extend_from_slice(&frame_header.serialize());

        let compressed_data = self.compress_block(input)?;
        output.extend_from_slice(&compressed_data);

        Ok(output)
    }

    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let compressed = self.compress_block(input)?;
        output.extend_from_slice(&compressed);
        self.window.push_slice(input);
        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Decompressor for ZstdDecompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        if input.len() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Input too short for ZSTD frame"));
        }

        let magic = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        if magic != ZSTD_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ZSTD magic number"));
        }

        self.window.clear();

        let (frame_header, header_size) = FrameHeader::parse(&input[4..])?;
        let _ = frame_header.version;
        let data_start = 4 + header_size;
        if data_start > input.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Frame header exceeds input"));
        }

        if data_start == input.len() {
            return Ok(Vec::new());
        }

        self.decompress_blocks(input, data_start)
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let decompressed = self.decompress(input)?;
        output.extend_from_slice(&decompressed);
        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Default for ZstdDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_zstd_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(ZSTD_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(ZSTD_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "zstd blob missing header/body separator",
    ))
}

fn parse_secure_zstd_blob_meta(header: &str, body_len: usize) -> io::Result<SecureZstdBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != ZSTD_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid zstd blob magic",
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
                format!("invalid zstd header line '{}'", line),
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
            "missing nonce in zstd blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in zstd blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in zstd blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in zstd blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in zstd blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in zstd blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "zstd encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureZstdBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

mod tests {
    use super::*;

    #[test]
    fn test_zstd_empty() {
        let data = b"";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_small() {
        let data = b"Hello, World!";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.starts_with(&ZSTD_MAGIC.to_le_bytes()));
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_repeated() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_levels() {
        let data = b"The quick brown fox jumps over the lazy dog";

        for &level in &[
            CompressionLevel::Fast,
            CompressionLevel::Default,
            CompressionLevel::Best,
        ] {
            let compressed = compress(data, level).unwrap();
            let decompressed = decompress(&compressed).unwrap();
            assert_eq!(data, decompressed.as_slice());
        }
    }

    #[test]
    fn test_zstd_compressor_reset() {
        let mut compressor = ZstdCompressor::new(CompressionLevel::Default);

        let data1 = b"first";
        let compressed1 = compressor.compress(data1).unwrap();

        compressor.reset();

        let data2 = b"second";
        let compressed2 = compressor.compress(data2).unwrap();

        assert_ne!(compressed1, compressed2);

        let decompressed1 = decompress(&compressed1).unwrap();
        let decompressed2 = decompress(&compressed2).unwrap();

        assert_eq!(data1, decompressed1.as_slice());
        assert_eq!(data2, decompressed2.as_slice());
    }

    #[test]
    fn test_zstd_large_data() {
        let mut data = Vec::new();
        for i in 0..5000 {
            data.extend_from_slice(&format!("Line {}: Zstandard compression test\n", i).into_bytes());
        }

        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_zstd_magic_number() {
        let data = b"test";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() >= 4);
        let magic = u32::from_le_bytes([compressed[0], compressed[1], compressed[2], compressed[3]]);
        assert_eq!(magic, ZSTD_MAGIC);
    }

    #[test]
    fn test_zstd_frame_header_parsing() {
        let data = b"test data for zstandard";
        let compressed = compress(data, CompressionLevel::Default).unwrap();

        let result = decompress(&compressed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zstd_random_data() {
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();

        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_zstd_quality_levels() {
        let data = b"The quick brown fox jumps over the lazy dog. ";
        let data_repeated: Vec<u8> = data.iter().cloned().cycle().take(500).collect();

        let fast = compress(&data_repeated, CompressionLevel::Fast).unwrap();
        let default = compress(&data_repeated, CompressionLevel::Default).unwrap();
        let _best = compress(&data_repeated, CompressionLevel::Best).unwrap();

        assert_eq!(decompress(&fast).unwrap(), data_repeated);
        assert_eq!(decompress(&default).unwrap(), data_repeated);
    }

    #[test]
    fn test_zstd_binary_data() {
        let data: Vec<u8> = vec![0, 1, 2, 3, 255, 254, 253, 127, 128];
        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_zstd_frame_header_flags() {
        let data = b"test";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() >= 5);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_single_byte() {
        let data = b"X";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_invalid_magic_number() {
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
        let result = decompress(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_zstd_truncated_data() {
        let data = b"test data";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let truncated = &compressed[0..compressed.len().saturating_sub(3)];
        let result = decompress(truncated);
        assert!(result.is_err() || result.unwrap().is_empty());
    }

    #[test]
    fn test_zstd_decompressor_reset() {
        let mut decompressor = ZstdDecompressor::new();
        let data1 = b"first test";
        let compressed1 = compress(data1, CompressionLevel::Default).unwrap();
        let result1 = decompressor.decompress(&compressed1).unwrap();
        assert_eq!(data1, result1.as_slice());

        decompressor.reset();

        let data2 = b"second test";
        let compressed2 = compress(data2, CompressionLevel::Default).unwrap();
        let result2 = decompressor.decompress(&compressed2).unwrap();
        assert_eq!(data2, result2.as_slice());
    }

    #[test]
    fn test_zstd_unicode_data() {
        let data = "Hello, 世界! Привет мир! 🦀".as_bytes();
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_secure_zstd_blob_roundtrip_identity() {
        let payload = b"zstd secure payload identity".to_vec();
        let (meta, blob) =
            encode_secure_zstd_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_zstd_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_zstd_blob_roundtrip_zstd() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let (meta, blob) = encode_secure_zstd_payload(&payload, CompressionAlgorithm::Zstd).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Zstd);

        let (decoded_meta, restored) = decode_secure_zstd_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_zstd_blob_tamper_detection() {
        let payload = b"tamper".to_vec();
        let (_, mut blob) =
            encode_secure_zstd_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_zstd_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}