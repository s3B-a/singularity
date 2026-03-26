use super::{Compressor, Decompressor, CompressionLevel};
use super::utils::{BitReader, BitWriter, SlidingWindow};
use std::io;

const BROTLI_MIN_WINDOW_SIZE: usize = 16;
const BROTLI_MAX_WINDOW_SIZE: usize = 24;
const BROTLI_WINDOW_BITS: usize = 24;
const BROTLI_MAX_DISTANCE: usize = 1 << BROTLI_WINDOW_BITS;
const BROTLI_MAX_LENGTH: usize = 262144;
const BROTLI_MIN_LENGTH: usize = 4;

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
                    )
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
        if input.len() < 4 || &input[0..4] != &[0xce, 0xb2, 0xcf, 0x81] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Brotli magic number"
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
        assert_eq!(data.len(), decompressed.len(), 
            "Length mismatch: expected {}, got {}", 
            data.len(), decompressed.len());
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
}