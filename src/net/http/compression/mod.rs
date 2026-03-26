pub mod gzip;
pub mod deflate;
pub mod brotli;
pub mod zstd;
pub mod utils;

use std::io;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

impl CompressionAlgorithm {
    pub fn content_encoding(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
            CompressionAlgorithm::Identity => "identity",
        }
    }

    pub fn from_content_encoding(encoding: &str) -> Option<Self> {
        match encoding {
            "gzip" | "x-gzip" => Some(CompressionAlgorithm::Gzip),
            "deflate" => Some(CompressionAlgorithm::Deflate),
            "br" => Some(CompressionAlgorithm::Brotli),
            "zstd" => Some(CompressionAlgorithm::Zstd),
            "identity" => Some(CompressionAlgorithm::Identity),
            _ => None,
        }
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gz",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zst",
            CompressionAlgorithm::Identity => "",
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            CompressionAlgorithm::Gzip => 4,
            CompressionAlgorithm::Deflate => 3,
            CompressionAlgorithm::Brotli => 5,
            CompressionAlgorithm::Zstd => 6,
            CompressionAlgorithm::Identity => 0,
        }
    }

    pub fn is_implemented(&self) -> bool {
        match self {
            CompressionAlgorithm::Gzip => true,
            CompressionAlgorithm::Deflate => true,
            CompressionAlgorithm::Brotli => true,
            CompressionAlgorithm::Zstd => true,
            CompressionAlgorithm::Identity => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    Fast,
    Default,
    Best,
    Custom(u8),
}

impl CompressionLevel {
    pub fn deflate_level(&self) -> u8 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 9,
            CompressionLevel::Custom(level) => (*level).min(9),
        }
    }

    pub fn brotli_level(&self) -> u8 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 11,
            CompressionLevel::Custom(level) => (*level).min(11),
        }
    }

    pub fn zstd_level(&self) -> i32 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 3,
            CompressionLevel::Best => 22,
            CompressionLevel::Custom(level) => (*level as i32).min(22),
        }
    }
}

pub trait Compressor {
    fn compress(&mut self, input: &[u8]) -> io::Result<Vec<u8>>;
    fn compress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<Vec<u8>>;
    fn reset(&mut self);
}

pub trait Decompressor {
    fn decompress(&mut self, input: &[u8]) -> io::Result<Vec<u8>>;
    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<Vec<u8>>;
    fn reset(&mut self);
}

#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub algorithms: Vec<CompressionAlgorithm>,
    pub min_size: usize,
    pub max_size: Option<usize>,
    pub level: CompressionLevel,
    pub excluded_content_types: Vec<String>,
    pub prefer_algorithm: Option<CompressionAlgorithm>,
}

impl CompressionConfig {
    pub fn should_compress_content_type(&self, content_type: &str) -> bool {
        let content_type_lower = content_type.to_lowercase();
        for excluded in &self.excluded_content_types {
            if content_type_lower.starts_with(&excluded.to_lowercase()) {
                return false;
            }
        }

        true
    }

    pub fn should_compress_size(&self, size: usize) -> bool {
        if size < self.min_size {
            return false;
        }

        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        true
    }

    pub fn negotiate_algorithm(&self, accpet_encoding: &str) -> Option<CompressionAlgorithm> {
        let accepted = parse_accept_encoding(accpet_encoding);
        for algo in &self.algorithms {
            if accepted.iter().any(|(enc, _)| enc == algo) {
                if algo.is_implemented() {
                    return Some(*algo);
                }
            }
        }

        if accepted.iter().any(|(enc, _)| *enc == CompressionAlgorithm::Identity) {
            return Some(CompressionAlgorithm::Identity);
        }

        None
    }
}

pub fn parse_accept_encoding(accept_encoding: &str) -> Vec<(CompressionAlgorithm, f32)> {
    let mut encodings = Vec::new();
    for part in accept_encoding.split(',') {
        let part = part.trim();
        let (encoding, quality) = if let Some((enc, q)) = part.split_once(';') {
            let enc = enc.trim();
            let q_value = q.trim().strip_prefix("q=").and_then(|v| v.parse::<f32>().ok()).unwrap_or(1.0);
            (enc, q_value)
        } else {
            (part, 1.0)
        };

        if let Some(algo) = CompressionAlgorithm::from_content_encoding(encoding) {
            encodings.push((algo, quality));
        }
    }

    encodings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    encodings
}

pub fn compress(algorithm: CompressionAlgorithm, data: &[u8], level: CompressionLevel) -> io::Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Gzip => gzip::compress(data, level),
        CompressionAlgorithm::Deflate => deflate::compress(data, level),
        CompressionAlgorithm::Brotli => brotli::compress(data, level),
        CompressionAlgorithm::Zstd => zstd::compress(data, level),
        CompressionAlgorithm::Identity => Ok(data.to_vec()),
    }
}

pub fn decompress(algorithm: CompressionAlgorithm, data: &[u8]) -> io::Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Gzip => gzip::decompress(data),
        CompressionAlgorithm::Deflate => deflate::decompress(data),
        CompressionAlgorithm::Brotli => brotli::decompress(data),
        CompressionAlgorithm::Zstd => zstd::decompress(data),
        CompressionAlgorithm::Identity => Ok(data.to_vec()),
    }
}

pub fn detect_algorithm(data: &[u8]) -> Option<CompressionAlgorithm> {
    if data.len() < 2 {
        return None;
    }

    if data[0] == 0x1f && data[1] == 0x8b {
        return Some(CompressionAlgorithm::Gzip);
    }

    if data.len() >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        return Some(CompressionAlgorithm::Zstd)
    }

    if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA) {
        return Some(CompressionAlgorithm::Deflate);
    }

    None
}

impl Default for CompressionLevel {
    fn default() -> Self {
        CompressionLevel::Default
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithms: vec![
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Zstd,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Deflate,
            ],
            min_size: 860,
            max_size: Some(10 * 1024 * 1024),
            level: CompressionLevel::Default,
            excluded_content_types: vec![
                // Images
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "image/webp".to_string(),
                "image/avif".to_string(),
                // Video
                "video/".to_string(),
                // Audio
                "audio/".to_string(),
                // Already compressed
                "application/zip".to_string(),
                "application/gzip".to_string(),
                "application/x-bzip2".to_string(),
                "application/x-7z-compressed".to_string(),
                "application/x-rar-compressed".to_string(),
            ],
            prefer_algorithm: Some(CompressionAlgorithm::Brotli),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_content_encoding() {
        assert_eq!(CompressionAlgorithm::Gzip.content_encoding(), "gzip");
        assert_eq!(CompressionAlgorithm::Deflate.content_encoding(), "deflate");
        assert_eq!(CompressionAlgorithm::Brotli.content_encoding(), "br");
        assert_eq!(CompressionAlgorithm::Zstd.content_encoding(), "zstd");
        assert_eq!(CompressionAlgorithm::Identity.content_encoding(), "identity");
    }

    #[test]
    fn test_algorithm_from_content_encoding() {
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("gzip"),
            Some(CompressionAlgorithm::Gzip)
        );
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("x-gzip"),
            Some(CompressionAlgorithm::Gzip)
        );
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("br"),
            Some(CompressionAlgorithm::Brotli)
        );
        assert_eq!(
            CompressionAlgorithm::from_content_encoding("unknown"),
            None
        );
    }

    #[test]
    fn test_compression_level_values() {
        assert_eq!(CompressionLevel::Fast.deflate_level(), 1);
        assert_eq!(CompressionLevel::Default.deflate_level(), 6);
        assert_eq!(CompressionLevel::Best.deflate_level(), 9);
        assert_eq!(CompressionLevel::Custom(5).deflate_level(), 5);
        assert_eq!(CompressionLevel::Custom(20).deflate_level(), 9); // clamped
    }

    #[test]
    fn test_parse_accept_encoding() {
        let result = parse_accept_encoding("gzip, deflate, br");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, CompressionAlgorithm::Gzip);
        assert_eq!(result[0].1, 1.0);
    }

    #[test]
    fn test_parse_accept_encoding_with_quality() {
        let result = parse_accept_encoding("gzip;q=0.8, br;q=1.0, deflate;q=0.5");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, CompressionAlgorithm::Brotli);
        assert_eq!(result[0].1, 1.0);
        assert_eq!(result[1].0, CompressionAlgorithm::Gzip);
        assert_eq!(result[1].1, 0.8);
    }

    #[test]
    fn test_config_should_compress_content_type() {
        let config = CompressionConfig::default();
        
        assert!(config.should_compress_content_type("text/html"));
        assert!(config.should_compress_content_type("application/json"));
        assert!(!config.should_compress_content_type("image/jpeg"));
        assert!(!config.should_compress_content_type("video/mp4"));
    }

    #[test]
    fn test_config_should_compress_size() {
        let config = CompressionConfig::default();
        
        assert!(!config.should_compress_size(500)); // Too small
        assert!(config.should_compress_size(1000)); // Good size
        assert!(!config.should_compress_size(20 * 1024 * 1024)); // Too large
    }

    #[test]
    fn test_detect_gzip() {
        let gzip_header = vec![0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(detect_algorithm(&gzip_header), Some(CompressionAlgorithm::Gzip));
    }

    #[test]
    fn test_detect_zstd() {
        let zstd_header = vec![0x28, 0xB5, 0x2F, 0xFD];
        assert_eq!(detect_algorithm(&zstd_header), Some(CompressionAlgorithm::Zstd));
    }

    #[test]
    fn test_algorithm_priority() {
        assert!(CompressionAlgorithm::Brotli.priority() > CompressionAlgorithm::Gzip.priority());
        assert!(CompressionAlgorithm::Zstd.priority() > CompressionAlgorithm::Deflate.priority());
    }
}