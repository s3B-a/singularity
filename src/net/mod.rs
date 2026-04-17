pub mod tcp;
pub mod udp;
pub mod socket;
pub mod http;
pub mod https;
pub mod dns;
pub mod cookie;
pub mod connection_pool;

pub use tcp::{TcpStream, TcpListener};
pub use udp::UdpSocket;
pub use http::{HttpClient, HttpServer, HttpRequest, HttpResponse, HttpMethod, HttpVersion};
pub use https::{HttpsServer, HttpsClient};
pub use dns::DnsResolver;
pub use cookie::CookieJar;

pub use crate::crypto as crypto;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub type NetResult<T> = Result<T, NetErr>;

const NET_SECURE_ENVELOPE_MAGIC: &str = "SINGULARITY_NET_SECURE_ENVELOPE_V1";
const NET_SECURE_ENVELOPE_CONTEXT: &str = "SINGULARITY_NET_SECURE_ENVELOPE_BINDING_V1";

#[derive(Debug)]
pub enum NetErr {
    Io(io::Error),
    ConnectionFailed(String),
    Timeout,
    InvalidAddr,
    DnsResFailed,
    InvalidResponse,
    ConnectionClosed,
    Http3Error(String),
    ProtocolError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureNetEnvelopeMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

impl From<io::Error> for NetErr {
    fn from(err: io::Error) -> Self {
        NetErr::Io(err)
    }
}

impl From<crate::net::http::http3::Error> for NetErr {
    fn from(err: crate::net::http::http3::Error) -> Self {
        NetErr::Http3Error(format!("{}", err))
    }
}

impl std::fmt::Display for NetErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetErr::Io(e) => write!(f, "IO Error: {}", e),
            NetErr::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            NetErr::Timeout => write!(f, "Connection Timeout"),
            NetErr::InvalidAddr => write!(f, "Invalid Address"),
            NetErr::DnsResFailed => write!(f, "DNS Resolution Failed"),
            NetErr::InvalidResponse => write!(f, "Invalid Response"),
            NetErr::ConnectionClosed => write!(f, "Connection Closed"),
            NetErr::Http3Error(msg) => write!(f, "HTTP/3 Error: {}", msg),
            NetErr::ProtocolError(msg) => write!(f, "Protocol Error: {}", msg),
        }
    }
}

impl std::error::Error for NetErr {}

pub fn select_secure_compression_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_net_payload(raw_payload: &[u8], algorithm: CompressionAlgorithm) -> io::Result<(SecureNetEnvelopeMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.to_vec()
    } else {
        compression::compress(selected_algorithm, raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure net nonce: {}", e),
        )
    })?;

    let digest = sha256(raw_payload);
    let tag = compute_envelope_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureNetEnvelopeMeta {
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
        magic = NET_SECURE_ENVELOPE_MAGIC,
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

pub fn encode_secure_net_payload_auto(raw_payload: &[u8], accept_encoding: &str) -> io::Result<(SecureNetEnvelopeMeta, Vec<u8>)> {
    let algorithm = select_secure_compression_algorithm(accept_encoding);
    encode_secure_net_payload(raw_payload, algorithm)
}

pub fn decode_secure_net_payload(secure_blob: &[u8]) -> io::Result<(SecureNetEnvelopeMeta, Vec<u8>)> {
    let (header, body) = split_header_body(secure_blob)?;
    let meta = parse_secure_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nonce encoding in secure net envelope",
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest encoding in secure net envelope",
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tag encoding in secure net envelope",
        )
    })?;

    let computed_tag = compute_envelope_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope tag verification failed",
        ));
    }

    let decoded_payload = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        compression::decompress(meta.algorithm, body)?
    };

    if decoded_payload.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded payload size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded_payload.len()
            ),
        ));
    }

    let computed_digest = sha256(&decoded_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope digest verification failed",
        ));
    }

    Ok((meta, decoded_payload))
}

fn compute_envelope_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(NET_SECURE_ENVELOPE_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    let hmac_key = sha256(&key_material);

    let mut signed = Vec::new();
    signed.extend_from_slice(NET_SECURE_ENVELOPE_MAGIC.as_bytes());
    signed.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    signed.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &signed)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope header separator not found",
        )
    })?;

    let header = String::from_utf8(data[..split_pos].to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope header is not valid UTF-8",
        )
    })?;

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_meta(header: &str, body_len: usize) -> io::Result<SecureNetEnvelopeMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != NET_SECURE_ENVELOPE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure net envelope magic",
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
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported secure net content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("tag=HMAC-SHA-256=") {
            tag_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("issued-at=") {
            issued_at_unix = v.trim().parse::<u64>().ok();
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope missing nonce",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope missing digest",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure net envelope missing tag")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope encoded-size mismatch",
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure net envelope missing issued-at",
        )
    })?;

    Ok(SecureNetEnvelopeMeta {
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
    fn test_secure_net_roundtrip_identity() {
        let payload = b"hello secure net".to_vec();
        let (meta, blob) =
            encode_secure_net_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded) = decode_secure_net_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_net_roundtrip_gzip() {
        let payload = b"repeat repeat repeat repeat repeat repeat repeat".to_vec();
        let (meta, blob) = encode_secure_net_payload(&payload, CompressionAlgorithm::Gzip).unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (decoded_meta, decoded) = decode_secure_net_payload(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_net_tamper_detection() {
        let payload = b"tamper-target".to_vec();
        let (_, mut blob) =
            encode_secure_net_payload(&payload, CompressionAlgorithm::Identity).unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = decode_secure_net_payload(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_secure_compression_algorithm() {
        let algo = select_secure_compression_algorithm("br;q=0.2, gzip;q=0.9, identity;q=0.1");
        assert_eq!(algo, CompressionAlgorithm::Gzip);
    }

    #[test]
    fn test_auto_secure_encoding() {
        let payload = b"auto select".to_vec();
        let (meta, _) = encode_secure_net_payload_auto(&payload, "zstd, gzip;q=0.8").unwrap();
        assert_ne!(meta.algorithm, CompressionAlgorithm::Identity);
    }
}