use super::deflate;
use super::utils::crc32;
use super::{CompressionAlgorithm, CompressionLevel, Compressor, Decompressor};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const GZIP_MAGIC: u16 = 0x8b1f;
const DEFLATE_METHOD: u8 = 8;
const GZIP_HEADER_SIZE: usize = 10;

const FTEXT: u8 = 0x01;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

const GZIP_BLOB_MAGIC: &str = "SINGULARITY_HTTP_GZIP_BLOB_V1";
const GZIP_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_GZIP_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureGzipBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub struct GzipCompressor {
    deflate: deflate::DeflateCompressor,
    crc: u32,
    size: u32,
}

impl GzipCompressor {
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            deflate: deflate::DeflateCompressor::new(level),
            crc: 0xffffffff,
            size: 0,
        }
    }

    fn write_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(GZIP_HEADER_SIZE);
        header.push((GZIP_MAGIC & 0xff) as u8);
        header.push(((GZIP_MAGIC >> 8) & 0xff) as u8);
        header.push(DEFLATE_METHOD);
        header.push(0);

        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
        header.extend_from_slice(&mtime.to_le_bytes());
        header.push(0);
        header.push(3);

        header
    }

    fn write_trailer(&self, crc: u32, size: u32) -> Vec<u8> {
        let mut trailer = Vec::with_capacity(8);
        trailer.extend_from_slice(&crc.to_le_bytes());
        trailer.extend_from_slice(&size.to_le_bytes());

        trailer
    }
}

pub struct GzipDecompressor {
    deflate: deflate::DeflateDecompressor,
    crc: u32,
    size: u32,
    expected_crc: Option<u32>,
    expected_size: Option<u32>,
    header_read: bool,
    trailer_read: bool,
}

impl GzipDecompressor {
    pub fn new() -> Self {
        Self {
            deflate: deflate::DeflateDecompressor::new(),
            crc: 0xffffffff,
            size: 0,
            expected_crc: None,
            expected_size: None,
            header_read: false,
            trailer_read: false,
        }
    }

    fn read_header(data: &[u8]) -> io::Result<(usize, u8)> {
        if data.len() < GZIP_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GZIP header too short",
            ));
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != GZIP_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid GZIP magic number",
            ));
        }

        if data[2] != DEFLATE_METHOD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported compression method",
            ));
        }

        let flags = data[3];
        let mut offset = GZIP_HEADER_SIZE;
        if flags & FEXTRA != 0 {
            if offset + 2 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GZIP extra field too short",
                ));
            }

            let extra_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + extra_len;
            if offset > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GZIP extra field overflow",
                ));
            }
        }

        if flags & FNAME != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }

            if offset >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GZIP filename not null-terminated",
                ));
            }

            offset += 1;
        }

        if flags & FCOMMENT != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }

            if offset >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GZIP comment not null-terminated",
                ));
            }

            offset += 1;
        }

        if flags & FHCRC != 0 {
            offset += 2;
            if offset > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GZIP header CRC overflow",
                ));
            }
        }

        Ok((offset, flags))
    }

    fn read_trailer(data: &[u8]) -> io::Result<(u32, u32)> {
        if data.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GZIP trailer too short",
            ));
        }

        let crc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Ok((crc, size))
    }
}

pub fn select_secure_gzip_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    super::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_gzip_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureGzipBlobMeta, Vec<u8>)> {
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
            format!("failed to generate gzip blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_gzip_blob_tag(
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
        magic = GZIP_BLOB_MAGIC,
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
        SecureGzipBlobMeta {
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

pub fn encode_secure_gzip_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureGzipBlobMeta, Vec<u8>)> {
    let selected = select_secure_gzip_algorithm(accept_encoding);
    encode_secure_gzip_payload(data, selected)
}

pub fn decode_secure_gzip_payload(data: &[u8]) -> io::Result<(SecureGzipBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_gzip_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid gzip nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid gzip digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid gzip tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gzip digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_gzip_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gzip blob HMAC mismatch",
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
                "gzip raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gzip blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

pub fn compress(data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    let mut compressor = GzipCompressor::new(level);
    compressor.compress(data)
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decompressor = GzipDecompressor::new();
    decompressor.decompress(data)
}

impl Compressor for GzipCompressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = self.write_header();
        let compressed = self.deflate.compress(input)?;
        output.extend_from_slice(&compressed);

        let crc = crc32(input);
        let size = input.len() as u32;
        output.extend_from_slice(&self.write_trailer(crc, size));

        Ok(output)
    }

    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if self.size == 0 {
            output.extend_from_slice(&self.write_header());
        }

        self.deflate.compress_stream(input, output)?;

        self.crc = super::utils::crc32_update(self.crc, input);
        self.size = self.size.wrapping_add(input.len() as u32);

        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        let mut output = self.deflate.finish()?;
        output.extend_from_slice(&self.write_trailer(self.crc ^ 0xffffffff, self.size));

        Ok(output)
    }

    fn reset(&mut self) {
        self.deflate.reset();
        self.crc = 0xffffffff;
        self.size = 0;
    }
}

impl Decompressor for GzipDecompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        let (header_size, _flags) = Self::read_header(input)?;
        if input.len() < header_size + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GZIP data too short",
            ));
        }

        let deflate_data_end = input.len() - 8;
        let deflate_data = &input[header_size..deflate_data_end];

        let output = self.deflate.decompress(deflate_data)?;
        let (crc, size) = Self::read_trailer(&input[deflate_data_end..])?;
        let calculated_crc = crc32(&output);
        if calculated_crc != crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRC32 mismatch: expected {}, got {}", crc, calculated_crc),
            ));
        }

        let calculated_size = output.len() as u32;
        if calculated_size != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Size mismatch: expected {}, got {}", size, calculated_size),
            ));
        }

        Ok(output)
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if !self.header_read {
            let (header_size, _flags) = Self::read_header(input)?;
            self.header_read = true;
            if input.len() > header_size + 8 {
                let deflate_data = &input[header_size..input.len() - 8];
                let decompressed = self.deflate.decompress(deflate_data)?;
                output.extend_from_slice(&decompressed);

                self.crc = super::utils::crc32_update(self.crc, &decompressed);
                self.size = self.size.wrapping_add(decompressed.len() as u32);

                let (crc, size) = Self::read_trailer(&input[input.len() - 8..])?;
                self.expected_crc = Some(crc);
                self.expected_size = Some(size);
                self.trailer_read = true;
            }
        } else if !self.trailer_read && input.len() >= 8 {
            let (crc, size) = Self::read_trailer(&input[input.len() - 8..])?;
            if crc != (self.crc ^ 0xffffffff) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("CRC32 mismatch: expected {}, got {}", crc, self.crc ^ 0xffffffff),
                ));
            }

            if size != self.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Size mismatch: expected {}, got {}", size, self.size),
                ));
            }

            self.trailer_read = true;
        }

        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        if self.header_read && self.trailer_read {
            Ok(Vec::new())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GZIP decompression not finished",
            ))
        }
    }

    fn reset(&mut self) {
        self.deflate.reset();
        self.crc = 0xffffffff;
        self.size = 0;
        self.expected_crc = None;
        self.expected_size = None;
        self.header_read = false;
        self.trailer_read = false;
    }
}

fn compute_gzip_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(GZIP_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(GZIP_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "gzip blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "gzip blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "gzip blob missing header/body separator",
    ))
}

fn parse_secure_gzip_blob_meta(header: &str, body_len: usize) -> io::Result<SecureGzipBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != GZIP_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid gzip blob magic",
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
                format!("invalid gzip header line '{}'", line),
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
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid tag header"))?.to_string();
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
            "missing nonce in gzip blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in gzip blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in gzip blob header")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in gzip blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in gzip blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in gzip blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "gzip encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureGzipBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl Default for GzipDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_empty() {
        let data = b"";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() > 10);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_gzip_small() {
        let data = b"Hello, World!";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.starts_with(&[0x1f, 0x8b]));
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_gzip_repeated() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_gzip_levels() {
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
    fn test_gzip_magic_number() {
        let data = b"test";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);
        assert_eq!(compressed[2], 8);
    }

    #[test]
    fn test_gzip_crc_validation() {
        let data = b"test data";
        let mut compressed = compress(data, CompressionLevel::Default).unwrap();

        if compressed.len() >= 8 {
            let index = compressed.len() - 8;
            compressed[index] ^= 0xff;
            let result = decompress(&compressed);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_gzip_size_validation() {
        let data = b"test data";
        let mut compressed = compress(data, CompressionLevel::Default).unwrap();

        if compressed.len() >= 4 {
            let index = compressed.len() - 4;
            compressed[index] ^= 0xff;
            let result = decompress(&compressed);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_gzip_compressor_reset() {
        let mut compressor = GzipCompressor::new(CompressionLevel::Default);

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
    fn test_gzip_header_variants() {
        let data = b"test data";
        let compressed1 = compress(data, CompressionLevel::Default).unwrap();
        let compressed2 = compress(data, CompressionLevel::Default).unwrap();

        let decompressed1 = decompress(&compressed1).unwrap();
        let decompressed2 = decompress(&compressed2).unwrap();

        assert_eq!(decompressed1, decompressed2);
    }

    #[test]
    fn test_gzip_large_data() {
        let mut data = Vec::new();
        for i in 0..5000 {
            data.extend_from_slice(&format!("Line {}: Hello, World!\n", i).into_bytes());
        }

        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() > 0);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_secure_gzip_blob_roundtrip_identity() {
        let payload = b"gzip secure payload identity".to_vec();
        let (meta, blob) =
            encode_secure_gzip_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_gzip_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_gzip_blob_roundtrip_gzip() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let (meta, blob) = encode_secure_gzip_payload(&payload, CompressionAlgorithm::Gzip).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, restored) = decode_secure_gzip_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_gzip_blob_tamper_detection() {
        let payload = b"tamper".to_vec();
        let (_, mut blob) =
            encode_secure_gzip_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_gzip_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}