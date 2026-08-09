use super::utils::{adler32, BitReader, BitWriter, SlidingWindow};
use super::{CompressionAlgorithm, CompressionLevel, Compressor, Decompressor};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const BLOCKTYPE_UNCOMPRESSED: u8 = 0;
const BLOCKTYPE_FIXED_HUFFMAN: u8 = 1;
const BLOCKTYPE_DYNAMIC_HUFFMAN: u8 = 2;

const MAX_MATCH_DISTANCE: usize = 32768;
const MAX_MATCH_LENGTH: usize = 258;
const MIN_MATCH_LENGTH: usize = 3;
const MAX_UNCOMPRESSED_BLOCK_LEN: usize = 65535;

const DEFLATE_BLOB_MAGIC: &str = "SINGULARITY_HTTP_DEFLATE_BLOB_V1";
const DEFLATE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_DEFLATE_BLOB_BINDING_V1";

const FIXED_LITERAL_CODE_LENGTHS: [u8; 288] = {
    let mut lengths = [0u8; 288];
    let mut i = 0;
    while i < 144 {
        lengths[i] = 8;
        i += 1;
    }

    while i < 256 {
        lengths[i] = 9;
        i += 1;
    }

    while i < 280 {
        lengths[i] = 7;
        i += 1;
    }

    while i < 288 {
        lengths[i] = 8;
        i += 1;
    }

    lengths
};

const FIXED_DISTANCE_CODE_LENGTHS: [u8; 32] = [5; 32];

const LENGTH_CODES: [(u16, u8, u16); 29] = [
    (3, 0, 257), (4, 0, 258), (5, 0, 259), (6, 0, 260), (7, 0, 261),
    (8, 0, 262), (9, 0, 263), (10, 0, 264), (11, 1, 265), (13, 1, 266),
    (15, 1, 267), (17, 1, 268), (19, 2, 269), (23, 2, 270), (27, 2, 271),
    (31, 2, 272), (35, 3, 273), (43, 3, 274), (51, 3, 275), (59, 3, 276),
    (67, 4, 277), (83, 4, 278), (99, 4, 279), (115, 4, 280), (131, 5, 281),
    (163, 5, 282), (195, 5, 283), (227, 5, 284), (258, 0, 285),
];

const DISTANCE_CODES: [(u16, u8, u8); 30] = [
    (1, 0, 0), (2, 0, 1), (3, 0, 2), (4, 0, 3), (5, 1, 4), (7, 1, 5),
    (9, 2, 6), (13, 2, 7), (17, 3, 8), (25, 3, 9), (33, 4, 10), (49, 4, 11),
    (65, 5, 12), (97, 5, 13), (129, 6, 14), (193, 6, 15), (257, 7, 16),
    (385, 7, 17), (513, 8, 18), (769, 8, 19), (1025, 9, 20), (1537, 9, 21),
    (2049, 10, 22), (3073, 10, 23), (4097, 11, 24), (6145, 11, 25),
    (8193, 12, 26), (12289, 12, 27), (16385, 13, 28), (24577, 13, 29),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDeflateBlobMeta {
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
        if max_len == 0 {
            return Self { codes };
        }

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
                codes.push(HuffmanCode {symbol: symbol as u16, code, length: len});
            }
        }

        Self { codes }
    }

    fn encode(&self, symbol: u16) -> Option<(u16, u8)> {
        self.codes.iter().find(|c| c.symbol == symbol).map(|c| (c.code, c.length))
    }

    fn decode(&self, reader: &mut BitReader) -> Option<u16> {
        if self.codes.is_empty() {
            return None;
        }

        let mut code = 0u16;
        let max_bits = self.codes.iter().map(|c| c.length).max().unwrap_or(15) as usize;
        for bit_len in 1..=max_bits {
            let bit = reader.read_bits(1)? as u16;
            code = (code << 1) | bit;
            for huffman_code in &self.codes {
                if huffman_code.length == bit_len as u8 && huffman_code.code == code {
                    match huffman_code.symbol {
                        0..=255 | 256..=285 => return Some(huffman_code.symbol),
                        _ => return None,
                    }
                }
            }
        }

        None
    }
}

pub struct DeflateCompressor {
    level: CompressionLevel,
    window: SlidingWindow,
}

impl DeflateCompressor {
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            level,
            window: SlidingWindow::new(MAX_MATCH_DISTANCE),
        }
    }

    fn compress_block(&mut self, data: &[u8], final_block: bool) -> io::Result<Vec<u8>> {
        let mut writer = BitWriter::new();
        writer.write_bits(if final_block { 1 } else { 0 }, 1);
        self.write_uncompressed_block(&mut writer, data)?;
        Ok(writer.finish())
    }

    fn write_uncompressed_block(&self, writer: &mut BitWriter, data: &[u8]) -> io::Result<()> {
        writer.write_bits(BLOCKTYPE_UNCOMPRESSED as u32, 2);
        writer.align_to_byte();

        let len = data.len() as u16;
        let nlen = !len;

        writer.write_bits(len as u32, 16);
        writer.write_bits(nlen as u32, 16);
        for &byte in data {
            writer.write_bits(byte as u32, 8);
        }

        Ok(())
    }

    fn write_compressed_block(&mut self, writer: &mut BitWriter, data: &[u8]) -> io::Result<()> {
        let literal = HuffmanTree::build_from_lengths(&FIXED_LITERAL_CODE_LENGTHS);
        let distance = HuffmanTree::build_from_lengths(&FIXED_DISTANCE_CODE_LENGTHS);
        let mut i = 0;
        while i < data.len() {
            let remaining = &data[i..];
            let max_len = remaining.len().min(MAX_MATCH_LENGTH);
            if let Some((dist, length)) = self.window.find_match(remaining, max_len) {
                if length >= MIN_MATCH_LENGTH {
                    let (length_code, extra_bits, extra_len) = Self::get_length_code(length);
                    if let Some((code, code_len)) = literal.encode(length_code) {
                        writer.write_bits_reverse(code as u32, code_len);
                        if extra_len > 0 {
                            writer.write_bits(extra_bits as u32, extra_len);
                        }
                    }

                    let (dist_code, extra_bits, extra_len) = Self::get_distance_code(dist);
                    if let Some((code, code_len)) = distance.encode(dist_code) {
                        writer.write_bits_reverse(code as u32, code_len);
                        if extra_len > 0 {
                            writer.write_bits(extra_bits as u32, extra_len);
                        }
                    }

                    for j in 0..length {
                        self.window.push(data[i + j]);
                    }

                    i += length;
                    continue;
                }
            }

            let byte = data[i];
            if let Some((code, code_len)) = literal.encode(byte as u16) {
                writer.write_bits_reverse(code as u32, code_len);
            }

            self.window.push(byte);
            i += 1;
        }

        if let Some((code, code_len)) = literal.encode(256) {
            writer.write_bits_reverse(code as u32, code_len);
        }

        Ok(())
    }

    fn get_length_code(length: usize) -> (u16, u16, u8) {
        for &(base, extra_bits, code) in &LENGTH_CODES {
            let next_base = LENGTH_CODES.iter().find(|&&(b, _, _)| b > base).map(|&(b, _, _)| b).unwrap_or(259);
            if length >= base as usize && length < next_base as usize {
                let extra = (length - base as usize) as u16;
                return (code as u16, extra, extra_bits);
            }
        }

        (285, 0, 0)
    }

    fn get_distance_code(distance: usize) -> (u16, u16, u8) {
        for &(base, extra_bits, code) in &DISTANCE_CODES {
            let next_base = DISTANCE_CODES.iter().find(|&&(b, _, _)| b > base).map(|&(b, _, _)| b).unwrap_or(32769);
            if distance >= base as usize && distance < next_base as usize {
                let extra = (distance - base as usize) as u16;
                return (code as u16, extra, extra_bits);
            }
        }

        (29, 0, 0)
    }
}

pub struct DeflateDecompressor {
    window: SlidingWindow,
    max_output_size: Option<usize>,
}

impl DeflateDecompressor {
    pub fn new() -> Self {
        Self {
            window: SlidingWindow::new(MAX_MATCH_DISTANCE),
            max_output_size: None,
        }
    }

    pub fn with_limit(max_output_size: usize) -> Self {
        Self {
            window: SlidingWindow::new(MAX_MATCH_DISTANCE),
            max_output_size: Some(max_output_size),
        }
    }

    fn check_output_limit(&self, output_len: usize) -> io::Result<()> {
        if let Some(limit) = self.max_output_size {
            if output_len > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "decompressed output exceeds maximum allowed size of {} bytes",
                        limit
                    ),
                ));
            }
        }

        Ok(())
    }

    fn decompress_block(&mut self, reader: &mut BitReader) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            let bfinal = reader.read_bits(1).ok_or_else(
                ||io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF reading BFINAL"))?;
            let btype = reader.read_bits(2).ok_or_else(
                || io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF reading BTYPE"))? as u8;

            match btype {
                BLOCKTYPE_UNCOMPRESSED => {
                    self.read_uncompressed_block(reader, &mut output)?;
                }
                BLOCKTYPE_FIXED_HUFFMAN => {
                    self.read_fixed_huffman_block(reader, &mut output)?;
                }
                BLOCKTYPE_DYNAMIC_HUFFMAN => {
                    self.read_dynamic_huffman_block(reader, &mut output)?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData, "Invalid block type"));
                }
            }

            self.check_output_limit(output.len())?;
            if bfinal == 1 {
                break;
            }
        }

        Ok(output)
    }

    fn read_uncompressed_block(&mut self, reader: &mut BitReader, output: &mut Vec<u8>) -> io::Result<()> {
        reader.align_to_byte();
        let len = reader.read_bits(16).ok_or_else(
            || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading length"))? as u16;
        let nlen = reader.read_bits(16).ok_or_else(
            || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading nlen"))? as u16;
        
        if len != !nlen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid uncompressed block length"))
        }

        for _ in 0..len {
            let byte = reader.read_bits(8).ok_or_else(
                || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading byte"))? as u8;
            
            output.push(byte);
            self.window.push(byte);
        }

        Ok(())
    }

    fn read_fixed_huffman_block(&mut self, reader: &mut BitReader, output: &mut Vec<u8>) -> io::Result<()> {
        let literal = HuffmanTree::build_from_lengths(&FIXED_LITERAL_CODE_LENGTHS);
        let distance = HuffmanTree::build_from_lengths(&FIXED_DISTANCE_CODE_LENGTHS);
        if literal.codes.is_empty() || distance.codes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty Huffman trees"));
        }

        self.decode_huffman_data(reader, &literal, &distance, output)
    }

    fn read_dynamic_huffman_block(&mut self, reader: &mut BitReader, output: &mut Vec<u8>) -> io::Result<()> {
        let hlit = reader.read_bits(5).ok_or_else(
            || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))?+ 257;
        
        let hlit = hlit.min(286) as usize;
        
        let hdist = reader.read_bits(5).ok_or_else(
            || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))? + 1;
        
        let hdist = hdist.min(30) as usize;
        
        let hclen = reader.read_bits(4).ok_or_else(
            || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))? + 4;

        const CODE_LENGTH_ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
        ];

        let mut code_length_lengths = vec![0u8; 19];
        for i in 0..hclen as usize {
            if i >= CODE_LENGTH_ORDER.len() {
                break;
            }

            let len = reader.read_bits(3).ok_or_else(
                || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))?;
            
            code_length_lengths[CODE_LENGTH_ORDER[i]] = len as u8;
        }

        let code_length_tree = HuffmanTree::build_from_lengths(&code_length_lengths);
        let mut literal_lengths = Vec::new();
        while literal_lengths.len() < hlit {
            self.decode_code_lengths(reader, &code_length_tree, &mut literal_lengths)?;
        }

        literal_lengths.truncate(hlit);
        let mut distance_lengths = Vec::new();
        while distance_lengths.len() < hdist {
            self.decode_code_lengths(reader, &code_length_tree, &mut distance_lengths)?;
        }

        distance_lengths.truncate(hdist);
        let literal_tree = HuffmanTree::build_from_lengths(&literal_lengths);
        let distance_tree = HuffmanTree::build_from_lengths(&distance_lengths);

        self.decode_huffman_data(reader, &literal_tree, &distance_tree, output)
    }

    fn decode_code_lengths(&self, reader: &mut BitReader, tree: &HuffmanTree, lengths: &mut Vec<u8>) -> io::Result<()> {
        let symbol = tree.decode(reader).ok_or_else(
            || io::Error::new(io::ErrorKind::InvalidData, "Invalid code"))?;
        
        match symbol {
            0..=15 => {
                lengths.push(symbol as u8);
            }
            16 => {
                let repeat = reader.read_bits(2).ok_or_else(
                    || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))? + 3;
                
                let prev = *lengths.last().unwrap_or(&0);
                for _ in 0..repeat {
                    lengths.push(prev);
                }
            }
            17 => {
                let repeat = reader.read_bits(3).ok_or_else(
                    || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))? + 3;
                
                for _ in 0..repeat {
                    lengths.push(0);
                }
            }
            18 => {
                let repeat = reader.read_bits(7).ok_or_else(
                    || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))? + 11;
                
                for _ in 0..repeat {
                    lengths.push(0);
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid code length symbol",
                ));
            }
        }

        Ok(())
    }

    fn decode_distance(code: u16, reader: &mut BitReader) -> io::Result<(usize, u8)> {
        let code_idx = if code as usize >= DISTANCE_CODES.len() {
            DISTANCE_CODES.len() - 1
        } else {
            code as usize
        };

        let (base, extra_bits, _symbol_code) = DISTANCE_CODES[code_idx];
        let extra = if extra_bits > 0 {
            reader.read_bits(extra_bits).ok_or_else(
                || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading distance extra bits"))?
        } else {
            0
        };

        let distance = (base as u32 + extra) as usize;
        if distance == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid distance: 0"));
        }

        Ok((distance, extra_bits))
    }

    fn decode_length(code: u16, reader: &mut BitReader) -> io::Result<(usize, u8)> {
        if code < 257 || code as usize > 285 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, 
                format!("Invalid length code: {} (must be 257-285)", code)));
        }

        let code_index = (code - 257) as usize;
        if code_index >= LENGTH_CODES.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, 
                format!("Invalid length code index: {}", code_index)));
        }

        let (base, extra_bits, _) = LENGTH_CODES[code_index];

        let extra = if extra_bits > 0 {
            reader.read_bits(extra_bits).ok_or_else(
                || io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading length extra bits"))?
        } else {
            0
        };

        let length = (base as u32 + extra) as usize;
        Ok((length, extra_bits))
    }

    fn decode_huffman_data(&mut self, reader: &mut BitReader, literal_tree: &HuffmanTree, distance_tree: &HuffmanTree, output: &mut Vec<u8>) -> io::Result<()> {
        loop {
            let symbol = literal_tree.decode(reader);
            match symbol {
                Some(0..=255) => {
                    let sym = symbol.unwrap();
                    output.push(sym as u8);
                    self.window.push(sym as u8);
                }
                Some(256) => {
                    break;
                }
                Some(257..=285) => {
                    let sym = symbol.unwrap();
                    let (length, _extra_bits) = Self::decode_length(sym, reader)?;

                    let dist_symbol = distance_tree.decode(reader);
                    if dist_symbol.is_none() {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid distance symbol"));
                    }

                    let dist_code = dist_symbol.unwrap();

                    let (distance, _) = Self::decode_distance(dist_code, reader)?;
                    for _ in 0..length {
                        if let Some(byte) = self.window.get(distance) {
                            output.push(byte);
                            self.window.push(byte);
                        } else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, 
                                format!("Invalid distance: {} (window pos: {})", distance, self.window.pos)));
                        }
                    }
                }
                Some(sym) if sym > 285 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid symbol: {} (must be 0-285 or 256)", sym)));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid symbol: {:?}", symbol)));
                }
            }

            self.check_output_limit(output.len())?;
        }

        Ok(())
    }
}

pub fn select_secure_deflate_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = super::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in &parsed {
        if *quality > 0.0 && *algorithm == CompressionAlgorithm::Deflate && algorithm.is_implemented() {
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

pub fn encode_secure_deflate_payload(data: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureDeflateBlobMeta, Vec<u8>)> {
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
            format!("failed to generate deflate blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_deflate_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = DEFLATE_BLOB_MAGIC,
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
        SecureDeflateBlobMeta {
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

pub fn encode_secure_deflate_payload_auto(data: &[u8], accept_encoding: &str) -> io::Result<(SecureDeflateBlobMeta, Vec<u8>)> {
    let selected = select_secure_deflate_algorithm(accept_encoding);
    encode_secure_deflate_payload(data, selected)
}

pub fn decode_secure_deflate_payload(data: &[u8]) -> io::Result<(SecureDeflateBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_deflate_blob_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid deflate nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid deflate digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid deflate tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deflate digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_deflate_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deflate blob HMAC mismatch",
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
                "deflate raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deflate blob digest mismatch",
        ));
    }

    Ok((meta, raw_payload))
}

impl Compressor for DeflateCompressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.window.clear();
        let _ = self.level;
        if input.is_empty() {
            return self.compress_block(&[], true);
        }

        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = input.chunks(MAX_UNCOMPRESSED_BLOCK_LEN).collect();

        for (i, chunk) in chunks.iter().enumerate() {
            let final_block = i + 1 == chunks.len();
            let block = self.compress_block(chunk, final_block)?;
            out.extend_from_slice(&block);
        }

        Ok(out)
    }

    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        for chunk in input.chunks(MAX_UNCOMPRESSED_BLOCK_LEN) {
            let block = self.compress_block(chunk, false)?;
            output.extend_from_slice(&block);
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Decompressor for DeflateDecompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut reader = BitReader::new(input);
        self.window.clear();
        self.decompress_block(&mut reader)
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut reader = BitReader::new(input);
        let result = self.decompress_block(&mut reader)?;
        output.extend_from_slice(&result);

        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.window.clear();
    }
}

impl Default for DeflateDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

pub fn compress(data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    let mut compressor = DeflateCompressor::new(level);
    compressor.compress(data)
}

pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decompressor = DeflateDecompressor::new();
    decompressor.decompress(data)
}

pub fn decompress_bounded(data: &[u8], max_output_size: usize) -> io::Result<Vec<u8>> {
    let mut decompressor = DeflateDecompressor::with_limit(max_output_size);
    decompressor.decompress(data)
}

fn compute_deflate_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(DEFLATE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(DEFLATE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "deflate blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "deflate blob header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "deflate blob missing header/body separator",
    ))
}

fn parse_secure_deflate_blob_meta(header: &str, body_len: usize) -> io::Result<SecureDeflateBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != DEFLATE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid deflate blob magic",
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
                format!("invalid deflate header line '{}'", line),
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
            "missing nonce in deflate blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in deflate blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in deflate blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in deflate blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in deflate blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in deflate blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "deflate encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureDeflateBlobMeta {
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
    fn test_deflate_empty() {
        let data = b"";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_deflate_small() {
        let data = b"Hello, World!";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_deflate_repeated() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = compress(data, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_deflate_levels() {
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
    fn test_huffman_tree() {
        let lengths = vec![3, 3, 3, 3, 3, 2, 4, 4];
        let tree = HuffmanTree::build_from_lengths(&lengths);
        assert!(!tree.codes.is_empty());
    }

    #[test]
    fn test_secure_deflate_blob_roundtrip_identity() {
        let payload = b"deflate secure payload identity".to_vec();
        let (meta, blob) =
            encode_secure_deflate_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_deflate_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_deflate_blob_roundtrip_deflate() {
        let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let (meta, blob) =
            encode_secure_deflate_payload(&payload, CompressionAlgorithm::Deflate).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Deflate);

        let (decoded_meta, restored) = decode_secure_deflate_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Deflate);
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_secure_deflate_blob_tamper_detection() {
        let payload = b"tamper".to_vec();
        let (_, mut blob) =
            encode_secure_deflate_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_deflate_payload(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_decompress_bounded_rejects_oversized_output() {
        let data = vec![b'a'; 200_000];
        let compressed = compress(&data, CompressionLevel::Best).unwrap();

        let result = decompress_bounded(&compressed, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_bounded_allows_output_under_limit() {
        let data = vec![b'a'; 1024];
        let compressed = compress(&data, CompressionLevel::Default).unwrap();

        let result = decompress_bounded(&compressed, 1024 * 1024).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_adler32_baseline() {
        let data = b"adler32-check";
        let checksum = adler32(data);
        assert_ne!(checksum, 0);
    }
}