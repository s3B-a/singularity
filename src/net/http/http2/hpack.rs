use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

// HPACK static table as per RFC 7541 Appendix A
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

const HPACK_CODEC_BLOB_MAGIC: &str = "SINGULARITY_HTTP2_HPACK_CODEC_BLOB_V1";
const HPACK_CODEC_BLOB_CONTEXT: &str = "SINGULARITY_HTTP2_HPACK_CODEC_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHpackCodecBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
struct HuffmanNode {
    symbol: Option<u16>,
    left: Option<Box<HuffmanNode>>,
    right: Option<Box<HuffmanNode>>,
}

impl HuffmanNode {
    fn new() -> Self {
        Self {
            symbol: None,
            left: None,
            right: None,
        }
    }

    fn leaf(symbol: u16) -> Self {
        Self {
            symbol: Some(symbol),
            left: None,
            right: None,
        }
    }
}

pub struct HpackCodec {
    dynamic_table: Vec<(String, String)>,
    max_dynamic_table_size: usize,
    huffman_root: HuffmanNode,
    huffman_codes: Vec<(u32, u8)>,
}

impl HpackCodec {
    pub fn new(max_size: usize) -> Self {
        let huffman_table = Self::get_huffman_codes();
        let huffman_root = Self::build_huffman_tree(&huffman_table);
        
        let mut huffman_codes = vec![(0u32, 0u8); 257];
        for (symbol, code, bit_len) in huffman_table {
            huffman_codes[symbol as usize] = (code, bit_len);
        }
        
        Self {
            dynamic_table: Vec::new(),
            max_dynamic_table_size: max_size,
            huffman_root,
            huffman_codes,
        }
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHpackCodecBlobMeta, Vec<u8>)> {
        encode_secure_hpack_codec(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHpackCodecBlobMeta, Vec<u8>)> {
        encode_secure_hpack_codec_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHpackCodecBlobMeta, Self)> {
        decode_secure_hpack_codec(data)
    }

    fn build_huffman_tree(codes: &[(u8, u32, u8)]) -> HuffmanNode {
        // Huffman codes from RFC 7541 Appendix B
        // Format: (symbol, code_bits, code_length)
        let mut root = HuffmanNode::new();
        for &(symbol, code, code_len) in codes {
            let symbol = symbol as u16;
            let mut node = &mut root;
            for i in 0..code_len {
                let bit = (code >> (code_len - 1 - i)) & 1;
                if i == code_len - 1 {
                    // Last bit - insert leaf
                    if bit == 0 {
                        node.left = Some(Box::new(HuffmanNode::leaf(symbol)));
                    } else {
                        node.right = Some(Box::new(HuffmanNode::leaf(symbol)));
                    }
                } else if bit == 0 {
                    if node.left.is_none() {
                        node.left = Some(Box::new(HuffmanNode::new()));
                    }
                    node = node.left.as_mut().expect("left exists");
                } else {
                    if node.right.is_none() {
                        node.right = Some(Box::new(HuffmanNode::new()));
                    }
                    node = node.right.as_mut().expect("right exists");
                }
            }
        }
        
        root
    }

    // RFC 7541 Appendix B - Huffman Code table
    // Returns (symbol, code, bit_length)
    // thanks AI for generating this table... I wasn't gonna type this out...
    fn get_huffman_codes() -> Vec<(u8, u32, u8)> {
        vec![
            (0, 0x1ff8, 13),
            (1, 0x7fffd8, 23),
            (2, 0xfffffe2, 28),
            (3, 0xfffffe3, 28),
            (4, 0xfffffe4, 28),
            (5, 0xfffffe5, 28),
            (6, 0xfffffe6, 28),
            (7, 0xfffffe7, 28),
            (8, 0xfffffe8, 28),
            (9, 0xffffea, 24),
            (10, 0x3ffffffc, 30),
            (11, 0xfffffe9, 28),
            (12, 0xfffffea, 28),
            (13, 0x3ffffffd, 30),
            (14, 0xfffffeb, 28),
            (15, 0xfffffec, 28),
            (16, 0xfffffed, 28),
            (17, 0xfffffee, 28),
            (18, 0xfffffef, 28),
            (19, 0xffffff0, 28),
            (20, 0xffffff1, 28),
            (21, 0xffffff2, 28),
            (22, 0x3ffffffe, 30),
            (23, 0xffffff3, 28),
            (24, 0xffffff4, 28),
            (25, 0xffffff5, 28),
            (26, 0xffffff6, 28),
            (27, 0xffffff7, 28),
            (28, 0xffffff8, 28),
            (29, 0xffffff9, 28),
            (30, 0xffffffa, 28),
            (31, 0xffffffb, 28),
            (32, 0x14, 6),
            (33, 0x3f8, 10),
            (34, 0x3f9, 10),
            (35, 0xffa, 12),
            (36, 0x1ff9, 13),
            (37, 0x15, 6),
            (38, 0xf8, 8),
            (39, 0x7fa, 11),
            (40, 0x3fa, 10),
            (41, 0x3fb, 10),
            (42, 0xf9, 8),
            (43, 0x7fb, 11),
            (44, 0xfa, 8),
            (45, 0x16, 6),
            (46, 0x17, 6),
            (47, 0x18, 6),
            (48, 0x0, 5),
            (49, 0x1, 5),
            (50, 0x2, 5),
            (51, 0x19, 6),
            (52, 0x1a, 6),
            (53, 0x1b, 6),
            (54, 0x1c, 6),
            (55, 0x1d, 6),
            (56, 0x1e, 6),
            (57, 0x1f, 6),
            (58, 0x5c, 7),
            (59, 0xfb, 8),
            (60, 0x7ffc, 15),
            (61, 0x20, 6),
            (62, 0xffb, 12),
            (63, 0x3fc, 10),
            (64, 0x1ffa, 13),
            (65, 0x21, 6),
            (66, 0x5d, 7),
            (67, 0x5e, 7),
            (68, 0x5f, 7),
            (69, 0x60, 7),
            (70, 0x61, 7),
            (71, 0x62, 7),
            (72, 0x63, 7),
            (73, 0x64, 7),
            (74, 0x65, 7),
            (75, 0x66, 7),
            (76, 0x67, 7),
            (77, 0x68, 7),
            (78, 0x69, 7),
            (79, 0x6a, 7),
            (80, 0x6b, 7),
            (81, 0x6c, 7),
            (82, 0x6d, 7),
            (83, 0x6e, 7),
            (84, 0x6f, 7),
            (85, 0x70, 7),
            (86, 0x71, 7),
            (87, 0x72, 7),
            (88, 0xfc, 8),
            (89, 0x73, 7),
            (90, 0xfd, 8),
            (91, 0x1ffb, 13),
            (92, 0x7fff0, 19),
            (93, 0x1ffc, 13),
            (94, 0x3ffc, 14),
            (95, 0x22, 6),
            (96, 0x7ffd, 15),
            (97, 0x3, 5),
            (98, 0x23, 6),
            (99, 0x4, 5),
            (100, 0x24, 6),
            (101, 0x5, 5),
            (102, 0x25, 6),
            (103, 0x26, 6),
            (104, 0x27, 6),
            (105, 0x6, 5),
            (106, 0x74, 7),
            (107, 0x75, 7),
            (108, 0x28, 6),
            (109, 0x29, 6),
            (110, 0x2a, 6),
            (111, 0x7, 5),
            (112, 0x2b, 6),
            (113, 0x76, 7),
            (114, 0x2c, 6),
            (115, 0x8, 5),
            (116, 0x9, 5),
            (117, 0x2d, 6),
            (118, 0x77, 7),
            (119, 0x78, 7),
            (120, 0x79, 7),
            (121, 0x7a, 7),
            (122, 0x7b, 7),
            (123, 0x7ffe, 15),
            (124, 0x7fc, 11),
            (125, 0x3ffd, 14),
            (126, 0x1ffd, 13),
            (127, 0xffffffc, 28),
            (128, 0xfffe6, 20),
            (129, 0x3fffd2, 22),
            (130, 0xfffe7, 20),
            (131, 0xfffe8, 20),
            (132, 0x3fffd3, 22),
            (133, 0x3fffd4, 22),
            (134, 0x3fffd5, 22),
            (135, 0x7fffd9, 23),
            (136, 0x3fffd6, 22),
            (137, 0x7fffda, 23),
            (138, 0x7fffdb, 23),
            (139, 0x7fffdc, 23),
            (140, 0x7fffdd, 23),
            (141, 0x7fffde, 23),
            (142, 0xffffeb, 24),
            (143, 0x7fffdf, 23),
            (144, 0xffffec, 24),
            (145, 0xffffed, 24),
            (146, 0x3fffd7, 22),
            (147, 0x7fffe0, 23),
            (148, 0xffffee, 24),
            (149, 0x7fffe1, 23),
            (150, 0x7fffe2, 23),
            (151, 0x7fffe3, 23),
            (152, 0x7fffe4, 23),
            (153, 0x1fffdc, 21),
            (154, 0x3fffd8, 22),
            (155, 0x7fffe5, 23),
            (156, 0x3fffd9, 22),
            (157, 0x7fffe6, 23),
            (158, 0x7fffe7, 23),
            (159, 0xffffef, 24),
            (160, 0x3fffda, 22),
            (161, 0x1fffdd, 21),
            (162, 0xfffe9, 20),
            (163, 0x3fffdb, 22),
            (164, 0x3fffdc, 22),
            (165, 0x7fffe8, 23),
            (166, 0x7fffe9, 23),
            (167, 0x1fffde, 21),
            (168, 0x7fffea, 23),
            (169, 0x3fffdd, 22),
            (170, 0x3fffde, 22),
            (171, 0xfffff0, 24),
            (172, 0x1fffdf, 21),
            (173, 0x3fffdf, 22),
            (174, 0x7fffeb, 23),
            (175, 0x7fffec, 23),
            (176, 0x1fffe0, 21),
            (177, 0x1fffe1, 21),
            (178, 0x3fffe0, 22),
            (179, 0x1fffe2, 21),
            (180, 0x7fffed, 23),
            (181, 0x3fffe1, 22),
            (182, 0x7fffee, 23),
            (183, 0x7fffef, 23),
            (184, 0xfffea, 20),
            (185, 0x3fffe2, 22),
            (186, 0x3fffe3, 22),
            (187, 0x3fffe4, 22),
            (188, 0x7ffff0, 23),
            (189, 0x3fffe5, 22),
            (190, 0x3fffe6, 22),
            (191, 0x7ffff1, 23),
            (192, 0x3ffffe0, 26),
            (193, 0x3ffffe1, 26),
            (194, 0xfffeb, 20),
            (195, 0x7fff1, 19),
            (196, 0x3fffe7, 22),
            (197, 0x7ffff2, 23),
            (198, 0x3fffe8, 22),
            (199, 0x1ffffec, 25),
            (200, 0x3ffffe2, 26),
            (201, 0x3ffffe3, 26),
            (202, 0x3ffffe4, 26),
            (203, 0x7ffffde, 27),
            (204, 0x7ffffdf, 27),
            (205, 0x3ffffe5, 26),
            (206, 0xfffff1, 24),
            (207, 0x1ffffed, 25),
            (208, 0x7fff2, 19),
            (209, 0x1fffe3, 21),
            (210, 0x3ffffe6, 26),
            (211, 0x7ffffe0, 27),
            (212, 0x7ffffe1, 27),
            (213, 0x3ffffe7, 26),
            (214, 0x7ffffe2, 27),
            (215, 0xfffff2, 24),
            (216, 0x1fffe4, 21),
            (217, 0x1fffe5, 21),
            (218, 0x3ffffe8, 26),
            (219, 0x3ffffe9, 26),
            (220, 0xffffffd, 28),
            (221, 0x7ffffe3, 27),
            (222, 0x7ffffe4, 27),
            (223, 0x7ffffe5, 27),
            (224, 0xfffec, 20),
            (225, 0xfffff3, 24),
            (226, 0xfffed, 20),
            (227, 0x1fffe6, 21),
            (228, 0x3fffe9, 22),
            (229, 0x1fffe7, 21),
            (230, 0x1fffe8, 21),
            (231, 0x7ffff3, 23),
            (232, 0x3fffea, 22),
            (233, 0x3fffeb, 22),
            (234, 0x1ffffee, 25),
            (235, 0x1ffffef, 25),
            (236, 0xfffff4, 24),
            (237, 0xfffff5, 24),
            (238, 0x3ffffea, 26),
            (239, 0x7ffff4, 23),
            (240, 0x3ffffeb, 26),
            (241, 0x7ffffe6, 27),
            (242, 0x3ffffec, 26),
            (243, 0x3ffffed, 26),
            (244, 0x7ffffe7, 27),
            (245, 0x7ffffe8, 27),
            (246, 0x7ffffe9, 27),
            (247, 0x7ffffea, 27),
            (248, 0x7ffffeb, 27),
            (249, 0xffffffe, 28),
            (250, 0x7ffffec, 27),
            (251, 0x7ffffed, 27),
            (252, 0x7ffffee, 27),
            (253, 0x7ffffef, 27),
            (254, 0x7fffff0, 27),
            (255, 0x3ffffee, 26),
        ]
    }

    pub fn encode(&mut self, headers: &HashMap<String, String>) -> Vec<u8> {
        // Encoding HPACK headers
        // Done by checking static table first
        // then encoding as indexed or literal header fields
        // according to the HPACK specification
        // https://datatracker.ietf.org/doc/html/rfc7541#section-2
        let mut output = Vec::new();
        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            if let Some(index) = self.find_in_static_table(&name_lower, value) {
                self.encode_indexed(&mut output, index);
            } else if let Some(index) = self.find_name_in_static_table(&name_lower) {
                output.push(0x40);
                self.encode_integer(&mut output, index, 6);
                self.encode_string_with_huffman(&mut output, value);
                self.add_to_dynamic_table(name_lower, value.clone());
            } else {
                output.push(0x40);
                self.encode_string_with_huffman(&mut output, &name_lower);
                self.encode_string_with_huffman(&mut output, value);
                self.add_to_dynamic_table(name_lower, value.clone());
            }
        }
        
        output
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<HashMap<String, String>, String> {
        // Decoding HPACK encoded headers
        // Done by reading the bytes and interpreting them
        // according to the HPACK specification
        let mut headers = HashMap::new();
        let mut pos = 0;
        while pos < data.len() {
            let byte = data[pos];
            if byte & 0x80 != 0 {
                let (index, consumed) = self.decode_integer(&data[pos..], 7)?;
                pos += consumed;
                
                if let Some((name, value)) = self.get_from_table(index) {
                    headers.insert(name, value);
                } else {
                    return Err(format!("Invalid table index: {}", index));
                }
            } else if byte & 0x40 != 0 {
                let (index, consumed) = self.decode_integer(&data[pos..], 6)?;
                pos += consumed;
                
                let (name, consumed_name) = if index == 0 {
                    self.decode_string(&data[pos..])?
                } else if let Some((n, _)) = self.get_from_table(index) {
                    (n, 0)
                } else {
                    return Err(format!("Invalid table index: {}", index));
                };
                pos += consumed_name;
                
                let (value, consumed_value) = self.decode_string(&data[pos..])?;
                pos += consumed_value;
                
                self.add_to_dynamic_table(name.clone(), value.clone());
                headers.insert(name, value);
            } else if byte & 0x20 != 0 {
                let (new_size, consumed) = self.decode_integer(&data[pos..], 5)?;
                self.max_dynamic_table_size = new_size;
                self.evict_to_fit();
                pos += consumed;
            } else {
                let (index, consumed) = self.decode_integer(&data[pos..], 4)?;
                pos += consumed;
                
                let (name, consumed_name) = if index == 0 {
                    self.decode_string(&data[pos..])?
                } else if let Some((n, _)) = self.get_from_table(index) {
                    (n, 0)
                } else {
                    return Err(format!("Invalid table index: {}", index));
                };
                pos += consumed_name;
                
                let (value, consumed_value) = self.decode_string(&data[pos..])?;
                pos += consumed_value;
                
                headers.insert(name, value);
            }
        }
        
        Ok(headers)
    }

    fn encode_indexed(&self, output: &mut Vec<u8>, index: usize) {
        if output.is_empty() {
            let mut byte = 0x80u8;
            if index < 127 {
                byte |= index as u8;
                output.push(byte);
            } else {
                output.push(byte | 0x7F);
                self.encode_integer(output, index - 127, 7);
            }
        }
    }

    fn find_in_static_table(&self, name: &str, value: &str) -> Option<usize> {
        STATIC_TABLE.iter().position(|(n, v)| *n == name && *v == value).map(|i| i + 1)
    }

    fn find_name_in_static_table(&self, name: &str) -> Option<usize> {
        STATIC_TABLE.iter().position(|(n, _)| *n == name).map(|i| i + 1)
    }

    fn get_from_table(&self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }
        
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Some((name.to_string(), value.to_string()));
        }
        
        let dynamic_index = index - STATIC_TABLE.len() - 1;
        self.dynamic_table.get(dynamic_index).map(|(n, v)| {
            (n.clone(), v.clone())
        })
    }

    fn add_to_dynamic_table(&mut self, name: String, value: String) {
        self.dynamic_table.insert(0, (name, value));
        self.evict_to_fit();
    }

    fn evict_to_fit(&mut self) {
        while self.current_dynamic_table_size() > self.max_dynamic_table_size && !self.dynamic_table.is_empty() {
            self.dynamic_table.pop();
        }
    }

    fn current_dynamic_table_size(&self) -> usize {
        self.dynamic_table.iter().map(|(n, v)| {
            n.len() + v.len() + 32
        }).sum()
    }

    fn encode_integer(&self, output: &mut Vec<u8>, mut value: usize, prefix_bits: u8) {
        // Encoding var-length integer
        // Done by using the prefix bits and continuing with bytes
        // with MSB set until the value is fully encoded
        let max_prefix = (1 << prefix_bits) - 1;
        if value < max_prefix {
            if output.is_empty() {
                output.push(value as u8);
            } else if let Some(last) = output.last_mut() {
                *last |= value as u8;
            }
        } else {
            if output.is_empty() {
                output.push(max_prefix as u8);
            } else if let Some(last) = output.last_mut() {
                *last |= max_prefix as u8;
            }
            
            value -= max_prefix;
            while value >= 128 {
                output.push((value % 128 + 128) as u8);
                value /= 128;
            }

            output.push(value as u8);
        }
    }

    fn decode_integer(&self, data: &[u8], prefix_bits: u8) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty data for integer decode".to_string());
        }
        
        let mask = (1 << prefix_bits) - 1;
        let mut value = (data[0] & mask as u8) as usize;
        if value < mask {
            return Ok((value, 1));
        }
        
        let mut pos = 1;
        let mut m = 0;
        loop {
            if pos >= data.len() {
                return Err("Incomplete integer".to_string());
            }
            
            let byte = data[pos] as usize;
            value += (byte & 0x7F) << m;
            if byte & 0x80 == 0 {
                return Ok((value, pos + 1));
            }
            
            pos += 1;
            m += 7;
            if m > 28 {
                return Err("Integer overflow".to_string());
            }
        }
    }

    fn encode_string_with_huffman(&self, output: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let huffman_encoded = self.huffman_encode(bytes);
        if huffman_encoded.len() < bytes.len() {
            let len_byte = 0x80 | (huffman_encoded.len() as u8);
            output.push(len_byte);
            output.extend_from_slice(&huffman_encoded);
        } else {
            self.encode_integer(output, bytes.len(), 7);
            output.extend_from_slice(bytes);
        }
    }

    fn decode_string(&self, data: &[u8]) -> Result<(String, usize), String> {
        if data.is_empty() {
            return Err("Empty data for string decode".to_string());
        }

        let huffman = data[0] & 0x80 != 0;
        let (length, consumed) = self.decode_integer(data, 7)?;
        if data.len() < consumed + length {
            return Err("Incomplete string data".to_string());
        }

        let string_data = &data[consumed..consumed + length];
        let s = if huffman {
            self.huffman_decode(string_data)?
        } else {
            String::from_utf8(string_data.to_vec())
                .map_err(|_| "Invalid UTF-8 in header string".to_string())?
        };

        Ok((s, consumed + length))
    }

    fn huffman_encode(&self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut current_byte = 0u8;
        let mut bits_used = 0u8;
        for &byte in data {
            let (code, bit_len) = self.huffman_codes[byte as usize];
            let mut remaining_bits = bit_len;
            let code_bits = code;
            while remaining_bits > 0 {
                let bits_to_write = (8 - bits_used).min(remaining_bits);
                let shift = remaining_bits - bits_to_write;
                let bits = ((code_bits >> shift) & ((1 << bits_to_write) - 1)) as u8;

                current_byte |= bits << (8 - bits_used - bits_to_write);
                bits_used += bits_to_write;
                remaining_bits -= bits_to_write;
                if bits_used == 8 {
                    output.push(current_byte);
                    current_byte = 0;
                    bits_used = 0;
                }
            }
        }

        if bits_used > 0 {
            current_byte |= (1 << (8 - bits_used)) - 1;
            output.push(current_byte);
        }

        output
    }

    fn huffman_decode(&self, data: &[u8]) -> Result<String, String> {
        let mut output = Vec::new();
        let mut node = &self.huffman_root;
        for &byte in data {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;
                node = if bit == 0 {
                    node.left.as_deref().ok_or("Invalid Huffman sequence")?
                } else {
                    node.right.as_deref().ok_or("Invalid Huffman sequence")?
                };
                
                if let Some(symbol) = node.symbol {
                    if symbol == 256 {
                        continue;
                    }
                    output.push(symbol as u8);
                    node = &self.huffman_root;
                }
            }
        }

        String::from_utf8(output).map_err(|_| "Invalid UTF-8 in Huffman decoded string".to_string())
    }
}

pub fn select_secure_hpack_codec_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_hpack_codec(codec: &HpackCodec, algorithm: CompressionAlgorithm) -> io::Result<(SecureHpackCodecBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_hpack_codec(codec);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate HPACK blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_hpack_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);

    let nonce_b64 = pem::encode(&nonce);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = HPACK_CODEC_BLOB_MAGIC,
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

    Ok((SecureHpackCodecBlobMeta {
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

pub fn encode_secure_hpack_codec_auto(codec: &HpackCodec, accept_encoding: &str) -> io::Result<(SecureHpackCodecBlobMeta, Vec<u8>)> {
    let selected = select_secure_hpack_codec_algorithm(accept_encoding);
    encode_secure_hpack_codec(codec, selected)
}

pub fn decode_secure_hpack_codec(data: &[u8]) -> io::Result<(SecureHpackCodecBlobMeta, HpackCodec)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_hpack_meta(&header, body.len())?;
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
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid tag encoding: {}", e))
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_hpack_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HPACK blob HMAC mismatch",
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
            "HPACK blob digest mismatch",
        ));
    }

    let codec = deserialize_hpack_codec(&raw_payload)?;
    Ok((meta, codec))
}

fn serialize_hpack_codec(codec: &HpackCodec) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!(
        "max-dynamic-table-size={}",
        codec.max_dynamic_table_size
    ));

    lines.push(format!("dynamic-count={}", codec.dynamic_table.len()));
    for (idx, (name, value)) in codec.dynamic_table.iter().enumerate() {
        lines.push(format!(
            "dynamic-{}-name={}",
            idx,
            pem::encode(name.as_bytes())
        ));

        lines.push(format!(
            "dynamic-{}-value={}",
            idx,
            pem::encode(value.as_bytes())
        ));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_hpack_codec(raw_payload: &[u8]) -> io::Result<HpackCodec> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HPACK payload is not valid UTF-8",
        )
    })?;

    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HPACK payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let max_dynamic_table_size = parse_usize(
        required_field(&kv, "max-dynamic-table-size")?,
        "max-dynamic-table-size",
    )?;

    let dynamic_count = parse_usize(required_field(&kv, "dynamic-count")?, "dynamic-count")?;
    let mut codec = HpackCodec::new(max_dynamic_table_size);
    codec.dynamic_table.clear();
    for idx in 0..dynamic_count {
        let name_bytes = decode_blob_field(
            required_field(&kv, &format!("dynamic-{}-name", idx))?,
            &format!("dynamic-{}-name", idx),
        )?;

        let value_bytes = decode_blob_field(
            required_field(&kv, &format!("dynamic-{}-value", idx))?,
            &format!("dynamic-{}-value", idx),
        )?;

        let name = String::from_utf8(name_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("dynamic-{}-name is not valid UTF-8", idx),
            )
        })?;

        let value = String::from_utf8(value_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("dynamic-{}-value is not valid UTF-8", idx),
            )
        })?;

        codec.dynamic_table.push((name, value));
    }

    codec.evict_to_fit();
    Ok(codec)
}

fn decode_blob_field(value: &str, field: &str) -> io::Result<Vec<u8>> {
    pem::decode(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in HPACK payload", key),
        )
    })
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn compute_hpack_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HPACK_CODEC_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HPACK_CODEC_BLOB_CONTEXT.as_bytes(), &mac_input)
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

fn parse_secure_hpack_meta(header: &str, body_len: usize) -> io::Result<SecureHpackCodecBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HPACK_CODEC_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure HPACK blob magic mismatch",
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
                format!("invalid secure HPACK header line '{}'", line),
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
                })?,);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?,);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?,);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure HPACK blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure HPACK blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure HPACK blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure HPACK blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure HPACK blob",
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
            "missing issued-at in secure HPACK blob",
        )
    })?;

    Ok(SecureHpackCodecBlobMeta {
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
    fn test_huffman_encode_decode() {
        let codec = HpackCodec::new(4096);

        let test_cases = vec![
            "www.example.com",
            "GET",
            "POST",
            "/index.html",
            "Mozilla/5.0",
            "gzip, deflate",
        ];

        for input in test_cases {
            let encoded = codec.huffman_encode(input.as_bytes());
            let decoded_str = codec.huffman_decode(&encoded).expect("Decode failed");
            assert_eq!(input, decoded_str, "Mismatch for: {}", input);
        }
    }

    #[test]
    fn test_huffman_compression() {
        let codec = HpackCodec::new(4096);

        let input = "www.example.com";
        let plain = input.as_bytes();
        let encoded = codec.huffman_encode(plain);

        assert!(encoded.len() < plain.len());
    }

    #[test]
    fn test_hpack_encode_decode() {
        let mut encoder = HpackCodec::new(4096);
        let mut decoder = HpackCodec::new(4096);

        let headers: HashMap<String, String> = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
            ("user-agent".to_string(), "test".to_string()),
        ]
        .into_iter()
        .collect();

        let encoded = encoder.encode(&headers);
        let decoded = decoder.decode(&encoded).expect("Decode failed");

        assert_eq!(headers, decoded);
    }

    #[test]
    fn test_secure_hpack_codec_roundtrip() {
        let mut codec = HpackCodec::new(4096);
        let headers: HashMap<String, String> = vec![
            ("x-test-header".to_string(), "alpha".to_string()),
            ("x-test-header-2".to_string(), "beta".to_string()),
        ]
        .into_iter()
        .collect();

        let _ = codec.encode(&headers);

        let (meta, blob) =
            encode_secure_hpack_codec(&codec, CompressionAlgorithm::Identity).expect("encode blob");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_hpack_codec(&blob).expect("decode blob");
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.max_dynamic_table_size, codec.max_dynamic_table_size);
        assert_eq!(restored.dynamic_table, codec.dynamic_table);
    }

    #[test]
    fn test_secure_hpack_codec_tamper_detection() {
        let codec = HpackCodec::new(4096);
        let (_, mut blob) =
            encode_secure_hpack_codec(&codec, CompressionAlgorithm::Identity).expect("encode blob");

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = decode_secure_hpack_codec(&blob);
        assert!(result.is_err());
    }
}