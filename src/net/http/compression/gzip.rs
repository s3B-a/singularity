use super::deflate;
use super::utils::crc32;
use super::{Compressor, Decompressor, CompressionLevel};
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
            return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP header too short"));
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != GZIP_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid GZIP magic number"));
        }

        if data[2] != DEFLATE_METHOD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported compression method"));
        }

        let flags = data[3];
        let mut offset = GZIP_HEADER_SIZE;
        if flags & FEXTRA != 0 {
            if offset + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP extra field too short"));
            }

            let extra_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + extra_len;
            if offset > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP extra field overflow"));
            }
        }

        if flags & FNAME != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }

            if offset >= data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP filename not null-terminated"));
            }

            offset += 1;
        }

        if flags & FCOMMENT != 0 {
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }

            if offset >= data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP comment not null-terminated"));
            }

            offset += 1;
        }

        if flags & FHCRC != 0 {
            offset += 2;
            if offset > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP header CRC overflow"));
            }
        }

        Ok((offset, flags))
    }

    fn read_trailer(data: &[u8]) -> io::Result<(u32, u32)> {
        if data.len() < 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP trailer too short"));
        }

        let crc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Ok((crc, size))
    }
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
            return Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP data too short"));
        }

        let deflate_data_end = input.len() - 8;
        let deflate_data = &input[header_size..deflate_data_end];

        let output = self.deflate.decompress(deflate_data)?;
        let (crc, size) = Self::read_trailer(&input[deflate_data_end..])?;
        let calculated_crc = crc32(&output);
        if calculated_crc != crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRC32 mismatch: expected {}, got {}", crc, calculated_crc)
            ));
        }

        let calculated_size = output.len() as u32;
        if calculated_size != size {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("Size mismatch: expected {}, got {}", size, calculated_size)));
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
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    format!("CRC32 mismatch: expected {}, got {}", crc, self.crc ^ 0xffffffff)));
            }

            if size != self.size {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    format!("Size mismatch: expected {}, got {}", size, self.size)));
            }

            self.trailer_read = true;
        }

        Ok(())
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        if self.header_read && self.trailer_read {
            Ok(Vec::new())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "GZIP decompression not finished"))
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

        for &level in &[CompressionLevel::Fast, CompressionLevel::Default, CompressionLevel::Best] {
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
}