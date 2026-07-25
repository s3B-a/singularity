pub mod client;
pub mod tls;
pub mod server;
pub mod trust_store;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;

pub use client::{HttpsClient, HttpsClientCfg, HttpsError};
pub use tls::{TlsCfg, TlsError, TlsStream};
pub use server::{HttpsServer, HttpsServerCfg};
pub use trust_store::{TrustStore, TrustStoreError};

pub const HTTPS_SECURE_ENVELOPE_MAGIC: &str = "SINGULARITY_HTTPS_SECURE_ENVELOPE_V1";
const HTTPS_SECURE_ENVELOPE_CTX: &str = "SINGULARITY_HTTPS_SECURE_TAG_CTX_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttpsEnvelopeMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
}

pub fn encode_secure_https_payload(raw_payload: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureHttpsEnvelopeMeta, Vec<u8>)> {
    let encoded_payload = if algorithm == CompressionAlgorithm::Identity {
        raw_payload.to_vec()
    } else {
        compression::compress(algorithm, raw_payload, CompressionLevel::Default)?
    };

    let mut nonce = [0u8; 24];
    random::fill_random(&mut nonce).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure envelope nonce: {}", e),
        )
    })?;

    let digest = sha256(&encoded_payload);
    let tag = compute_https_envelope_tag(&nonce, raw_payload.len(), algorithm, &encoded_payload);
    let nonce_b64 = pem::encode(&nonce);
    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let header = format!(
        "{magic}\ncontent-encoding: {encoding}\nnonce: {nonce}\ndigest: {digest}\ntag: {tag}\nraw-size: {raw_size}\nencoded-size: {encoded_size}\n\n",
        magic = HTTPS_SECURE_ENVELOPE_MAGIC,
        encoding = algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded_payload);

    Ok((
        SecureHttpsEnvelopeMeta {
            algorithm,
            nonce_b64,
            digest_b64,
            tag_b64,
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
        },
        out,
    ))
}

pub fn encode_secure_https_payload_auto(raw_payload: &[u8], accept_encoding: &str) -> io::Result<(SecureHttpsEnvelopeMeta, Vec<u8>)> {
    let algorithm = select_algorithm_from_accept_encoding(accept_encoding);
    encode_secure_https_payload(raw_payload, algorithm)
}

pub fn decode_secure_https_payload(secure_blob: &[u8]) -> io::Result<(SecureHttpsEnvelopeMeta, Vec<u8>)> {
    let (header, body) = split_header_body(secure_blob)?;
    let meta = parse_secure_https_meta(&header, body.len())?;
    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid secure envelope digest encoding")
    })?;

    let actual_digest = sha256(body);
    if !constant_time_eq(&expected_digest, &actual_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope digest verification failed",
        ));
    }

    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid secure envelope nonce encoding")
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid secure envelope tag encoding")
    })?;

    let actual_tag = compute_https_envelope_tag(&nonce, meta.raw_size, meta.algorithm, body);
    if !constant_time_eq(&expected_tag, &actual_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope tag verification failed",
        ));
    }

    let decoded = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        compression::decompress(meta.algorithm, body)?
    };

    if decoded.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure envelope raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded.len()
            ),
        ));
    }

    Ok((meta, decoded))
}

fn select_algorithm_from_accept_encoding(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algo, quality) in accepted {
        if quality > 0.0 && algo != CompressionAlgorithm::Identity && algo.is_implemented() {
            return algo;
        }
    }

    CompressionAlgorithm::Identity
}

fn compute_https_envelope_tag(nonce: &[u8], raw_size: usize, algorithm: CompressionAlgorithm, encoded_payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        HTTPS_SECURE_ENVELOPE_CTX.len() + nonce.len() + encoded_payload.len() + 32,
    );

    material.extend_from_slice(HTTPS_SECURE_ENVELOPE_CTX.as_bytes());
    material.extend_from_slice(nonce);
    material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    material.extend_from_slice(algorithm.content_encoding().as_bytes());
    material.push(0x0a);
    material.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    material.extend_from_slice(encoded_payload);

    sha256(&material)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "secure envelope header missing"))?;

    let header_str = std::str::from_utf8(&data[..split_pos])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secure envelope header invalid utf8"))?
        .to_string();

    Ok((header_str, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_https_meta(header: &str, body_len: usize) -> io::Result<SecureHttpsEnvelopeMeta> {
    let mut lines = header.lines();
    let magic = lines.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "secure envelope magic missing"))?;

    if magic != HTTPS_SECURE_ENVELOPE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut tag_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    for line in lines {
        let mut kv = line.splitn(2, ':');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        match key {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding: {}", value),
                    )
                })?;
            }
            "nonce" => nonce_b64 = value.to_string(),
            "digest" => digest_b64 = value.to_string(),
            "tag" => tag_b64 = value.to_string(),
            "raw-size" => {
                raw_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid secure envelope raw-size")
                })?)
            }
            "encoded-size" => {
                encoded_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid secure envelope encoded-size",
                    )
                })?)
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() || tag_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope metadata missing nonce, digest, or tag",
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope metadata missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure envelope metadata missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure envelope encoded-size mismatch: metadata {}, body {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttpsEnvelopeMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_https_payload_roundtrip_identity() {
        let payload = b"hello secure https".to_vec();
        let (meta, blob) =
            encode_secure_https_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_payload) = decode_secure_https_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_secure_https_payload_roundtrip_gzip() {
        let payload = b"payload payload payload payload payload payload".to_vec();
        let (meta, blob) = encode_secure_https_payload(&payload, CompressionAlgorithm::Gzip).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (_, decoded_payload) = decode_secure_https_payload(&blob).unwrap();
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_secure_https_payload_tamper_detection() {
        let payload = b"this should fail if modified".to_vec();
        let (_, mut blob) =
            encode_secure_https_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let err = decode_secure_https_payload(&blob).unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn test_secure_https_payload_auto_select() {
        let payload = b"auto encoding".to_vec();
        let (meta, _) =
            encode_secure_https_payload_auto(&payload, "zstd, br;q=0.9, gzip;q=0.8").unwrap();

        assert_ne!(meta.algorithm, CompressionAlgorithm::Identity);
    }
}