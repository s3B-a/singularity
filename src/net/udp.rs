use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const UDP_SECURE_DATAGRAM_MAGIC: &str = "SINGULARITY_UDP_SECURE_DATAGRAM_V1";
const UDP_SECURE_DATAGRAM_CONTEXT: &str = "SINGULARITY_UDP_SECURE_DATAGRAM_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureUdpDatagramMeta {
    pub algorithm: CompressionAlgorithm,
    pub integrity_enabled: bool,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct UdpSecurityCfg {
    pub enable_integrity: bool,
    pub nonce_len: usize,
}

#[derive(Debug, Clone)]
pub struct UdpCompressionCfg {
    pub enabled: bool,
    pub algorithm: CompressionAlgorithm,
    pub level: CompressionLevel,
    pub min_size: usize,
}

pub struct UdpSocket {
    socket: StdUdpSocket,
}

pub fn select_secure_udp_compression_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_udp_datagram(raw_payload: &[u8], security_cfg: &UdpSecurityCfg, compression_cfg: &UdpCompressionCfg) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>)> {
    let mut selected_algorithm = CompressionAlgorithm::Identity;
    if compression_cfg.enabled && raw_payload.len() >= compression_cfg.min_size {
        if compression_cfg.algorithm.is_implemented() {
            selected_algorithm = compression_cfg.algorithm;
        }
    }

    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.to_vec()
    } else {
        compression::compress(selected_algorithm, raw_payload, compression_cfg.level)?
    };

    let nonce = if security_cfg.enable_integrity {
        random::generate_random(security_cfg.nonce_len.max(8)).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate udp datagram nonce: {}", e),
            )
        })?
    } else {
        Vec::new()
    };

    let digest = sha256(raw_payload);
    let tag = if security_cfg.enable_integrity {
        compute_datagram_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload).to_vec()
    } else {
        Vec::new()
    };

    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureUdpDatagramMeta {
        algorithm: selected_algorithm,
        integrity_enabled: security_cfg.enable_integrity,
        nonce_b64: if security_cfg.enable_integrity {
            pem::encode(&nonce)
        } else {
            String::new()
        },
        digest_b64: pem::encode(&digest),
        tag_b64: if security_cfg.enable_integrity {
            pem::encode(&tag)
        } else {
            String::new()
        },
        raw_size: raw_payload.len(),
        encoded_size: encoded_payload.len(),
        issued_at_unix,
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nintegrity={integrity}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = UDP_SECURE_DATAGRAM_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        integrity = if meta.integrity_enabled { "on" } else { "off" },
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

pub fn decode_secure_udp_datagram(secure_datagram: &[u8], security_cfg: &UdpSecurityCfg) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>)> {
    let (header, body) = split_header_body(secure_datagram)?;
    let meta = parse_secure_datagram_meta(&header, body.len())?;
    if security_cfg.enable_integrity && !meta.integrity_enabled {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received udp secure datagram has integrity disabled",
        ));
    }

    if meta.integrity_enabled {
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce in udp secure datagram",
            )
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tag in udp secure datagram",
            )
        })?;

        let computed_tag = compute_datagram_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp secure datagram integrity verification failed",
            ));
        }
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
                "udp secure datagram size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded_payload.len()
            ),
        ));
    }

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest in udp secure datagram",
        )
    })?;

    let computed_digest = sha256(&decoded_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp secure datagram digest verification failed",
        ));
    }

    Ok((meta, decoded_payload))
}

impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(addr)?;
        Ok(Self { socket })
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        self.socket.connect(addr)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.socket.set_broadcast(broadcast)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    pub fn send_recv_timeout(&self, send_buf: &[u8], recv_buf: &mut [u8], addr: SocketAddr, timeout: Duration) -> io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))?;
        self.send_to(send_buf, addr)?;
        let (size, _) = self.recv_from(recv_buf)?;

        Ok(size)
    }

    pub fn send_secure_to(&self, payload: &[u8], addr: SocketAddr, security_cfg: &UdpSecurityCfg, compression_cfg: &UdpCompressionCfg) -> io::Result<(usize, SecureUdpDatagramMeta)> {
        let (meta, datagram) = encode_secure_udp_datagram(payload, security_cfg, compression_cfg)?;
        let sent = self.send_to(&datagram, addr)?;
        
        Ok((sent, meta))
    }

    pub fn send_secure_to_auto(&self, payload: &[u8], addr: SocketAddr, accept_encoding: &str) -> io::Result<(usize, SecureUdpDatagramMeta)> {
        let algorithm = select_secure_udp_compression_algorithm(accept_encoding);
        let mut compression_cfg = UdpCompressionCfg::default();
        compression_cfg.algorithm = algorithm;

        self.send_secure_to(payload, addr, &UdpSecurityCfg::default(), &compression_cfg)
    }

    pub fn recv_secure_from(&self, security_cfg: &UdpSecurityCfg, max_datagram_size: usize) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>, SocketAddr)> {
        if max_datagram_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_datagram_size must be > 0",
            ));
        }

        let mut datagram = vec![0u8; max_datagram_size];
        let (size, addr) = self.recv_from(&mut datagram)?;
        datagram.truncate(size);
        let (meta, payload) = decode_secure_udp_datagram(&datagram, security_cfg)?;
        
        Ok((meta, payload, addr))
    }

    pub fn recv_secure_from_default(&self, max_datagram_size: usize) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>, SocketAddr)> {
        self.recv_secure_from(&UdpSecurityCfg::default(), max_datagram_size)
    }

    pub fn send_secure(&self, payload: &[u8], security_cfg: &UdpSecurityCfg, compression_cfg: &UdpCompressionCfg) -> io::Result<SecureUdpDatagramMeta> {
        let (meta, datagram) = encode_secure_udp_datagram(payload, security_cfg, compression_cfg)?;
        self.send(&datagram)?;
        
        Ok(meta)
    }

    pub fn send_secure_auto(&self, payload: &[u8], accept_encoding: &str) -> io::Result<SecureUdpDatagramMeta> {
        let algorithm = select_secure_udp_compression_algorithm(accept_encoding);
        let mut compression_cfg = UdpCompressionCfg::default();
        compression_cfg.algorithm = algorithm;

        self.send_secure(payload, &UdpSecurityCfg::default(), &compression_cfg)
    }

    pub fn recv_secure(&self, security_cfg: &UdpSecurityCfg, max_datagram_size: usize) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>)> {
        if max_datagram_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_datagram_size must be > 0",
            ));
        }

        let mut datagram = vec![0u8; max_datagram_size];
        let size = self.recv(&mut datagram)?;
        datagram.truncate(size);

        decode_secure_udp_datagram(&datagram, security_cfg)
    }

    pub fn recv_secure_default(&self, max_datagram_size: usize) -> io::Result<(SecureUdpDatagramMeta, Vec<u8>)> {
        self.recv_secure(&UdpSecurityCfg::default(), max_datagram_size)
    }
}

impl Default for UdpSecurityCfg {
    fn default() -> Self {
        Self {
            enable_integrity: true,
            nonce_len: 24,
        }
    }
}

impl Default for UdpCompressionCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Brotli,
            level: CompressionLevel::Default,
            min_size: 512,
        }
    }
}

fn compute_datagram_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(UDP_SECURE_DATAGRAM_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    let hmac_key = sha256(&key_material);

    let mut signed = Vec::new();
    signed.extend_from_slice(UDP_SECURE_DATAGRAM_MAGIC.as_bytes());
    signed.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    signed.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &signed)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram header separator not found",
        )
    })?;

    let header = String::from_utf8(data[..split_pos].to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram header is not valid UTF-8",
        )
    })?;

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_datagram_meta(header: &str, body_len: usize) -> io::Result<SecureUdpDatagramMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != UDP_SECURE_DATAGRAM_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure udp datagram magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut integrity_enabled = false;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported udp secure datagram content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("integrity=") {
            let value = v.trim();
            integrity_enabled = value.eq_ignore_ascii_case("on")
                || value.eq_ignore_ascii_case("true")
                || value == "1";
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("tag=HMAC-SHA-256=") {
            tag_b64 = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("issued-at=") {
            issued_at_unix = v.trim().parse::<u64>().ok();
        }
    }

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram missing digest",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram missing encoded-size",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram missing issued-at",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure udp datagram body length mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    if integrity_enabled && (nonce_b64.is_empty() || tag_b64.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure udp datagram integrity is enabled but nonce/tag is missing",
        ));
    }

    Ok(SecureUdpDatagramMeta {
        algorithm,
        integrity_enabled,
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
    fn test_select_secure_udp_compression_algorithm() {
        let selected = select_secure_udp_compression_algorithm("identity;q=0.1, br;q=1.0");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let selected_identity = select_secure_udp_compression_algorithm("identity");
        assert_eq!(selected_identity, CompressionAlgorithm::Identity);
    }

    #[test]
    fn test_secure_udp_datagram_roundtrip_identity() {
        let payload = b"hello secure udp".to_vec();
        let security_cfg = UdpSecurityCfg::default();
        let compression_cfg = UdpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (meta, datagram) =
            encode_secure_udp_datagram(&payload, &security_cfg, &compression_cfg)
                .expect("encode must succeed");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_, decoded) =
            decode_secure_udp_datagram(&datagram, &security_cfg).expect("decode must succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_udp_datagram_roundtrip_compressed() {
        let payload = vec![b'a'; 4096];
        let security_cfg = UdpSecurityCfg::default();
        let compression_cfg = UdpCompressionCfg {
            enabled: true,
            algorithm: CompressionAlgorithm::Gzip,
            level: CompressionLevel::Default,
            min_size: 1,
        };

        let (meta, datagram) =
            encode_secure_udp_datagram(&payload, &security_cfg, &compression_cfg)
                .expect("encode must succeed");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (_, decoded) =
            decode_secure_udp_datagram(&datagram, &security_cfg).expect("decode must succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_udp_datagram_tamper_detected() {
        let payload = b"integrity check payload".to_vec();
        let security_cfg = UdpSecurityCfg::default();
        let compression_cfg = UdpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (_, mut datagram) =
            encode_secure_udp_datagram(&payload, &security_cfg, &compression_cfg)
                .expect("encode must succeed");

        let last = datagram.len().saturating_sub(1);
        datagram[last] ^= 0x01;

        let result = decode_secure_udp_datagram(&datagram, &security_cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_udp_datagram_requires_integrity_when_enabled() {
        let payload = b"no-integrity payload".to_vec();
        let no_integrity_cfg = UdpSecurityCfg {
            enable_integrity: false,
            nonce_len: 0,
        };

        let compression_cfg = UdpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (_, datagram) =
            encode_secure_udp_datagram(&payload, &no_integrity_cfg, &compression_cfg)
                .expect("encode must succeed");

        let result = decode_secure_udp_datagram(&datagram, &UdpSecurityCfg::default());
        assert!(result.is_err());
    }
}