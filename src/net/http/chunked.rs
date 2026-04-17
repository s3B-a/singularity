use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

const CHUNKED_BLOB_MAGIC: &str = "SINGULARITY_HTTP_CHUNKED_BLOB_V1";
const CHUNKED_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_CHUNKED_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureChunkedBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub fn select_secure_chunked_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_chunked_body(decoded_body: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureChunkedBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = encode_chunked_wire(decoded_body);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate chunked blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_chunked_blob_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureChunkedBlobMeta {
        algorithm: selected_algorithm,
        nonce_b64: pem::encode(&nonce),
        digest_b64: pem::encode(&digest),
        tag_b64: pem::encode(&tag),
        raw_size: raw_payload.len(),
        encoded_size: encoded_payload.len(),
        issued_at_unix,
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = CHUNKED_BLOB_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        nonce = meta.nonce_b64,
        digest = meta.digest_b64,
        tag = meta.tag_b64,
        raw_size = meta.raw_size,
        encoded_size = meta.encoded_size,
        issued_at = meta.issued_at_unix,
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded_payload);

    Ok((meta, out))
}

pub fn encode_secure_chunked_body_auto(decoded_body: &[u8], accept_encoding: &str) -> io::Result<(SecureChunkedBlobMeta, Vec<u8>)> {
    let algorithm = select_secure_chunked_algorithm(accept_encoding);
    encode_secure_chunked_body(decoded_body, algorithm)
}

pub fn decode_secure_chunked_body(data: &[u8]) -> io::Result<(SecureChunkedBlobMeta, Vec<u8>)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_chunked_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nonce encoding in chunked blob",
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest encoding in chunked blob",
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tag encoding in chunked blob",
        )
    })?;

    let computed_tag = compute_chunked_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked blob tag verification failed",
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
                "decoded chunked payload size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let computed_digest = sha256(&raw_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked blob digest verification failed",
        ));
    }

    let decoder = ChunkedDecoder::new(raw_payload.as_slice());
    let decoded_body = decoder.decode()?;

    Ok((meta, decoded_body))
}

fn encode_chunked_wire(body: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 4096;
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let end = (pos + CHUNK_SIZE).min(body.len());
        let chunk = &body[pos..end];

        out.extend_from_slice(format!("{:X}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");

        pos = end;
    }

    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn compute_chunked_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(CHUNKED_BLOB_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());

    let hmac_key = sha256(&key_material);
    hmac_sha256(&hmac_key, encoded_payload)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunked blob header is not utf-8: {}", e),
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunked blob header is not utf-8: {}", e),
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "chunked blob is missing header separator",
    ))
}

fn parse_secure_chunked_meta(header: &str, body_len: usize) -> io::Result<SecureChunkedBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != CHUNKED_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid chunked blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunked blob header line '{}'", line),
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
                })?;
                digest_b64 = Some(parsed.to_string());
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?;
                tag_b64 = Some(parsed.to_string());
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in chunked blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in chunked blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in chunked blob")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in chunked blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in chunked blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in chunked blob header")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in chunked blob header",
        )
    })?;
    
    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in chunked blob header",
        )
    })?;
    
    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in chunked blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "chunked blob encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureChunkedBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

pub struct ChunkedDecoder<R> {
    reader: R,
}

impl<R: Read> ChunkedDecoder<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn decode(mut self) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let chunk_size_line = self.read_line()?;
            let chunk_size = self.parse_chunk_size(&chunk_size_line)?;
            if chunk_size == 0 {
                // Read trailing headers if any and final CRLF
                self.read_trailing_headers()?;
                break;
            }

            let mut chunk_data = vec![0u8; chunk_size];
            self.reader.read_exact(&mut chunk_data)?;
            body.extend_from_slice(&chunk_data);
            self.read_line()?;
        }

        Ok(body)
    }

    fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        let mut buffer = [0u8; 1];
        loop {
            self.reader.read_exact(&mut buffer)?;
            let ch = buffer[0] as char;
            if ch == '\n' {
                break;
            }

            if ch != 'r' {
                line.push(ch);
            }
        }

        Ok(line)
    }

    fn parse_chunk_size(&self, line: &str) -> io::Result<usize> {
        let size_part = line.split(';').next().unwrap_or(line).trim();
        usize::from_str_radix(size_part, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {}", line),
            )
        })
    }

    fn read_trailing_headers(&mut self) -> io::Result<()> {
        loop {
            let line = self.read_line()?;
            if line.is_empty() {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_simple_chunk() {
        let data = b"5\r\nHello\r\n0\r\n\r\n";
        let decoder = ChunkedDecoder::new(&data[..]);
        let result = decoder.decode().unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_decode_multiple_chunks() {
        let data = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoder = ChunkedDecoder::new(&data[..]);
        let result = decoder.decode().unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_secure_chunked_roundtrip_identity() {
        let body = b"hello secure chunked world";
        let (meta, blob) = encode_secure_chunked_body(body, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_body) = decode_secure_chunked_body(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn test_secure_chunked_roundtrip_gzip() {
        let body = b"gzip gzip gzip gzip gzip gzip gzip";
        let (meta, blob) = encode_secure_chunked_body(body, CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, decoded_body) = decode_secure_chunked_body(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn test_secure_chunked_tamper_detection() {
        let body = b"tamper me";
        let (_, mut blob) = encode_secure_chunked_body(body, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = decode_secure_chunked_body(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_secure_chunked_algorithm() {
        let selected = select_secure_chunked_algorithm("br;q=0.9, gzip;q=0.8, identity;q=0.1");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let fallback = select_secure_chunked_algorithm("identity;q=1.0");
        assert_eq!(fallback, CompressionAlgorithm::Identity);
    }
}