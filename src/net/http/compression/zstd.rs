use super::{Compressor, Decompressor, CompressionLevel};
use super::utils::SlidingWindow;
use std::io;

const ZSTD_MAGIC: u32 = 0x28B52FFD;
const ZSTD_MIN_WINDOW_SIZE: u32 = 1024;
const ZSTD_MAX_WINDOW_SIZE: u32 = 1 << 31;
const ZSTD_DEFAULT_BLOCK_SIZE: usize = 128 * 1024;
const ZSTD_MIN_MATCH_LENGTH: usize = 3;
const ZSTD_MAX_MATCH_LENGTH: usize = 131072;

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
                        block_size, 
                        offset,
                        data.len())
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

        let (_frame_header, header_size) = FrameHeader::parse(&input[4..])?;
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

        for &level in &[CompressionLevel::Fast, CompressionLevel::Default, CompressionLevel::Best] {
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
        let magic = u32::from_le_bytes([
            compressed[0],
            compressed[1],
            compressed[2],
            compressed[3],
        ]);
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
}