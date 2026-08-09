use super::utils::{BitReader, BitWriter, SlidingWindow};
use super::{CompressionAlgorithm, CompressionLevel, Compressor, Decompressor};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const BROTLI_MIN_WINDOW_SIZE: usize = 16;
const BROTLI_MAX_WINDOW_SIZE: usize = 24;
const BROTLI_WINDOW_BITS: usize = 24;
const BROTLI_MAX_DISTANCE: usize = 1 << BROTLI_WINDOW_BITS;
const BROTLI_MAX_LENGTH: usize = 262144;
const BROTLI_MIN_LENGTH: usize = 4;

const BROTLI_BLOB_MAGIC: &str = "SINGULARITY_HTTP_BROTLI_BLOB_V1";
const BROTLI_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_BROTLI_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureBrotliBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
struct HuffmanCode {
    symbol: u16,
    code: u16,
    length: u8,
}

#[derive(Debug, Clone)]
struct HuffmanTree {
    codes: Vec<HuffmanCode>,
}

impl HuffmanTree {
    fn build_from_lengths(code_lengths: &[u8]) -> Self {
        let mut codes = Vec::new();
        let max_len = *code_lengths.iter().max().unwrap_or(&0) as usize;
        let mut bl_count = vec![0u16; max_len + 1];
        for &len in code_lengths {
            if len > 0 {
                bl_count[len as usize] += 1;
            }
        }

        let mut next_code = vec![0u16; max_len + 1];
        let mut code = 0u16;
        for bits in 1..=max_len {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (symbol, &len) in code_lengths.iter().enumerate() {
            if len > 0 {
                let code = next_code[len as usize];
                next_code[len as usize] += 1;
                codes.push(HuffmanCode {
                    symbol: symbol as u16,
                    code,
                    length: len,
                });
            }
        }

        Self { codes }
    }

    fn encode(&self, symbol: u16) -> Option<(u16, u8)> {
        self.codes.iter().find(|c| c.symbol == symbol).map(|c| (c.code, c.length))
    }

    fn decode(&self, reader: &mut BitReader) -> Option<u16> {
        let mut code = 0u16;
        for bit_len in 1..=15 {
            let bit = reader.read_bits(1)? as u16;
            code = (code << 1) | bit;
            for huffman_code in &self.codes {
                if huffman_code.length == bit_len && huffman_code.code == code {
                    return Some(huffman_code.symbol);
                }
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    symbol: u16,
    code: u32,
    length: u8,
}

#[derive(Debug)]
struct BrotliDict {
    words: Vec<Vec<u8>>,
}

impl BrotliDict {
    fn new() -> Self {
        Self {
            words: Vec::new(),
        }
    }

    fn lookup(&self, id: u16) -> Option<&[u8]> {
        if (id as usize) < self.words.len() {
            Some(&self.words[id as usize])
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct BrotliMetablock {
    data: Vec<u8>,
    meta_type: u8,
    last_metablock: bool,
    is_uncompressed: bool,
}

pub struct BrotliCompressor {
    level: CompressionLevel,
    window: SlidingWindow,
    dictionary: BrotliDict,
    quality: u32,
    mode: u32,
}

impl BrotliCompressor {
    pub fn new(level: CompressionLevel) -> Self {
        let quality = match level {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 11,
            CompressionLevel::Custom(q) => q.min(11) as u32,
        };

        Self {
            level,
            window: SlidingWindow::new(BROTLI_MAX_DISTANCE),
            dictionary: BrotliDict::new(),
            quality,
            mode: 0,
        }
    }

    fn compress_metablock(&mut self, data: &[u8], is_last: bool) -> io::Result<Vec<u8>> {
        let mut writer = BitWriter::new();
        writer.write_bits(if is_last { 1 } else { 0 }, 1);

        let mlen = data.len();
        let mnibbles = if mlen == 0 {
            0
        } else if mlen < 256 {
            1
        } else if mlen < 65536 {
            2
        } else {
            3
        };

        writer.write_bits(mnibbles as u32, 2);
        if mnibbles > 0 && mlen > 0 {
            for i in 0..mnibbles {
                let byte = ((mlen >> (i * 8)) & 0xFF) as u32;
                writer.write_bits(byte, 8);
            }
        }

        writer.align_to_byte();

        let mut result = writer.finish();
        result.extend_from_slice(data);

        self.window.push_slice(data);

        Ok(result)
    }

    fn compress_literals(&mut self, output: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        for &byte in data {
            self.write_bits(output, byte as u32, 8)?;
        }

        Ok(())
    }

    fn find_match(&self, data: &[u8], pos: usize, max_size: usize) -> Option<(usize, usize)> {
        if pos == 0 {
            return None;
        }

        let remaining = &data[pos..];
        let max_len = max_size.min(remaining.len()).min(BROTLI_MAX_LENGTH);
        let best = self.window.find_match(remaining, max_len)?;
        if best.1 >= BROTLI_MIN_LENGTH {
            Some(best)
        } else {
            None
        }
    }

    fn write_bits(&self, output: &mut Vec<u8>, value: u32, nbits: u32) -> io::Result<()> {
        let mut current_byte = 0u8;
        let mut bits_filled = 0;
        for i in 0..nbits {
            let bit = (value >> i) & 1;
            current_byte |= (bit as u8) << bits_filled;
            bits_filled += 1;

            if bits_filled == 8 {
                output.push(current_byte);
                current_byte = 0;
                bits_filled = 0;
            }
        }

        if bits_filled > 0 {
            output.push(current_byte);
        }

        Ok(())
    }

    fn encode_empty_metablock(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write_bits(&mut output, 1, 4).unwrap();
        self.write_bits(&mut output, 0, 4).unwrap();
        output
    }

    fn encode_huffman_tree(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut code_lengths = vec![0u8; 256];
        for &byte in data {
            code_lengths[byte as usize] += 1;
        }

        let huffman_tree = HuffmanTree::build_from_lengths(&code_lengths);
        for code in &huffman_tree.codes {
            self.write_bits(&mut output, code.symbol as u32, 8)?;
            self.write_bits(&mut output, code.length as u32, 5)?;
        }

        Ok(output)
    }
}

pub struct BrotliDecompressor {
    window: SlidingWindow,
    dictionary: BrotliDict,
}

impl BrotliDecompressor {
    pub fn new() -> Self {
        Self {
            window: SlidingWindow::new(1 << 24),
            dictionary: BrotliDict::new(),
        }
    }

    fn decompress_metablock(&mut self, input: &[u8], offset: &mut usize) -> io::Result<(Vec<u8>, bool)> {
        if *offset >= input.len() {
            return Ok((Vec::new(), true));
        }

        let start_offset = *offset;
        let mut reader = BitReader::new(&input[*offset..]);
        let islast = reader.read_bits(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EOF reading ISLAST"))?;
        
        let islast_flag = islast != 0;
        let mnibbles = reader.read_bits(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EOF reading MNIBBLES"))?;

        let mlen = if mnibbles > 0 {
            let mut len = 0usize;
            for i in 0..mnibbles {
                let byte = reader.read_bits(8)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EOF reading MLEN"))?;
                
                len |= (byte as usize) << (i * 8);
            }

            len
        } else {
            0
        };

        reader.align_to_byte();
        let header_size = reader.position();
        *offset = start_offset + header_size;
        if mlen > 0 {
            if *offset + mlen > input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Metablock data extends beyond input: need {} bytes at offset {}, have {} total",
                        mlen, *offset, input.len()
                    ),
                ));
            }
            
            let mut output = Vec::with_capacity(mlen);
            output.extend_from_slice(&input[*offset..*offset + mlen]);
            self.window.push_slice(&output);
            *offset += mlen;
            
            return Ok((output, islast_flag));
        }

        Ok((Vec::new(), islast_flag))
    }
}

pub fn select_secure_brotli_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = super::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in &parsed {
        if *quality > 0.0 && *algorithm == CompressionAlgorithm::Brotli && algorithm.is_implemented() {
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

pub fn encode_secure_brotli_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureBrotliBlobMeta, Vec<u8>)> {
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
            format!("failed to generate brotli blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_brotli_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = BROTLI_BLOB_MAGIC,
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
        SecureBrotliBlobMeta {
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

pub fn encode_secure_brotli_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureBrotliBlobMeta, Vec<u8>)> {
    let selected = select_secure_brotli_algorithm(accept_encoding);
    encode_secure_brotli_payload(data, selected)
}

pub fn decode_secure_brotli_payload(data: &[u8]) -> io::Result<(SecureBrotliBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_brotli_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid brotli nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid brotli digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid brotli tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "brotli digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_brotli_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "brotli blob HMAC mismatch",
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
                "brotli raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "brotli blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

impl Compressor for BrotliCompressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.window.clear();
        let mut output = Vec::new();
        output.extend_from_slice(&[0xce, 0xb2, 0xcf, 0x81]);
        let block_size = match self.quality {
            1..=3 => 8 * 1024,
            4..=8 => 16 * 1024,
            _ => 32 * 1024,
        };

        let chunks: Vec<_> = input.chunks(block_size).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i == chunks.len() - 1;
            let metablock = self.compress_metablock(chunk, is_last)?;
            output.extend_from_slice(&metablock);
        }

        Ok(output)
    }

    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let compressed = self.compress_metablock(input, false)?;
        output.extend_from_slice(&compressed);
        self.window.push_slice(input);
        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        writer.write_bits(0, 2);
        Ok(writer.finish())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Decompressor for BrotliDecompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        if input.len() < 4 || &input[0..4] != [0xce, 0xb2, 0xcf, 0x81] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Brotli magic number",
            ));
        }

        self.window.clear();
        let mut output = Vec::new();
        let mut offset = 4;
        loop {
            if offset >= input.len() {
                break;
            }

            let (metablock_output, islast) = self.decompress_metablock(input, &mut offset)?;
            output.extend_from_slice(&metablock_output);

            if islast {
                break;
            }
        }

        Ok(output)
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut offset = 0;
        let (metablock, _) = self.decompress_metablock(input, &mut offset)?;
        output.extend_from_slice(&metablock);
        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Default for BrotliDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

pub fn compress(data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    let mut compressor = BrotliCompressor::new(level);
    compressor.compress(data)
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decompressor = BrotliDecompressor::new();
    decompressor.decompress(data)
}

pub fn decompress_bounded(data: &[u8], max_output_size: usize) -> io::Result<Vec<u8>> {
    let mut decompressor = BrotliDecompressor::new();
    let mut output = Vec::new();
    if data.len() < 4 || &data[0..4] != [0xce, 0xb2, 0xcf, 0x81] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid Brotli magic number",
        ));
    }

    let mut offset = 4;
    loop {
        if offset >= data.len() {
            break;
        }

        let (metablock_output, islast) = decompressor.decompress_metablock(data, &mut offset)?;
        output.extend_from_slice(&metablock_output);
        if output.len() > max_output_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "decompressed output exceeds maximum allowed size of {} bytes",
                    max_output_size
                ),
            ));
        }

        if islast {
            break;
        }
    }

    Ok(output)
}

fn compute_brotli_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(BROTLI_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(BROTLI_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "brotli blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "brotli blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "brotli blob missing header/body separator",
    ))
}

fn parse_secure_brotli_blob_meta(header: &str, body_len: usize) -> io::Result<SecureBrotliBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != BROTLI_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid brotli blob magic",
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
                format!("invalid brotli header line '{}'", line),
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
            "missing nonce in brotli blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in brotli blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in brotli blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in brotli blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in brotli blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in brotli blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "brotli encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureBrotliBlobMeta {
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
    fn test_brotli_empty() {
        let data = b"";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_brotli_small() {
        let data = b"Hello, World!";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() > 0);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_brotli_repeated() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_brotli_levels() {
        let data = b"The quick brown fox jumps over the lazy dog";

        for &level in &[CompressionLevel::Fast, CompressionLevel::Default, CompressionLevel::Best] {
            let compressed = compress(data, level).unwrap();
            let decompressed = decompress(&compressed).unwrap();
            assert_eq!(data.to_vec(), decompressed, "Failed for level {:?}", level);
        }
    }

    #[test]
    fn test_brotli_quality_levels() {
        let data = b"The quick brown fox jumps over the lazy dog. ";

        let fast = compress(data, CompressionLevel::Fast).unwrap();
        let default = compress(data, CompressionLevel::Default).unwrap();
        let best = compress(data, CompressionLevel::Best).unwrap();

        assert_eq!(decompress(&fast).unwrap(), data.to_vec());
        assert_eq!(decompress(&default).unwrap(), data.to_vec());
        assert_eq!(decompress(&best).unwrap(), data.to_vec());
    }

    #[test]
    fn test_brotli_large_data() {
        let mut data = Vec::new();
        for i in 0..5000 {
            data.push((i % 256) as u8);
        }

        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_brotli_random_data() {
        let mut data = Vec::new();
        for i in 0..1280 {
            data.push((i % 256) as u8);
        }

        let compressed = compress(&data, CompressionLevel::Default).unwrap();
        assert!(compressed.len() > 0);
        assert_eq!(&compressed[0..4], &[0xce, 0xb2, 0xcf, 0x81]);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(
            data.len(),
            decompressed.len(),
            "Length mismatch: expected {}, got {}",
            data.len(),
            decompressed.len()
        );
        assert_eq!(data, decompressed, "Data mismatch");
    }

    #[test]
    fn test_brotli_compressor_reset() {
        let mut compressor = BrotliCompressor::new(CompressionLevel::Default);

        let data1 = b"first";
        let compressed1 = compressor.compress(data1).unwrap();

        compressor.reset();

        let data2 = b"second";
        let compressed2 = compressor.compress(data2).unwrap();

        assert_ne!(compressed1, compressed2);

        let decompressed1 = decompress(&compressed1).unwrap();
        let decompressed2 = decompress(&compressed2).unwrap();

        assert_eq!(data1.to_vec(), decompressed1);
        assert_eq!(data2.to_vec(), decompressed2);
    }

    #[test]
    fn test_secure_brotli_blob_roundtrip_identity() {
        let payload = b"brotli secure payload identity".to_vec();
        let (meta, blob) =
            encode_secure_brotli_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_brotli_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_brotli_blob_roundtrip_brotli() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let (meta, blob) =
            encode_secure_brotli_payload(&payload, CompressionAlgorithm::Brotli).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Brotli);

        let (decoded_meta, restored) = decode_secure_brotli_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Brotli);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_brotli_blob_tamper_detection() {
        let payload = b"tamper".to_vec();
        let (_, mut blob) =
            encode_secure_brotli_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_brotli_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}