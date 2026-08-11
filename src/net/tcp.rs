use super::socket::Socket;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TCP_SECURE_FRAME_MAGIC: &str = "SINGULARITY_TCP_SECURE_FRAME_V1";
const TCP_SECURE_FRAME_CONTEXT: &str = "SINGULARITY_TCP_SECURE_FRAME_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureTcpFrameMeta {
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
pub struct TcpSecurityCfg {
    pub enable_integrity: bool,
    pub nonce_len: usize,
}

#[derive(Debug, Clone)]
pub struct TcpCompressionCfg {
    pub enabled: bool,
    pub algorithm: CompressionAlgorithm,
    pub level: CompressionLevel,
    pub min_size: usize,
}

#[derive(Debug)]
pub struct TcpStream {
    socket: Socket,
    reader: BufReader<Socket>,
}

pub struct TcpListener {
    socket: Socket,
}

pub fn select_secure_tcp_compression_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_tcp_frame(raw_payload: &[u8], security_cfg: &TcpSecurityCfg, compression_cfg: &TcpCompressionCfg) -> io::Result<(SecureTcpFrameMeta, Vec<u8>)> {
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
                format!("failed to generate tcp frame nonce: {}", e),
            )
        })?
    } else {
        Vec::new()
    };

    let digest = sha256(raw_payload);
    let tag = if security_cfg.enable_integrity {
        compute_frame_tag(&nonce, selected_algorithm, raw_payload.len(), &encoded_payload).to_vec()
    } else {
        Vec::new()
    };

    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureTcpFrameMeta {
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
        magic = TCP_SECURE_FRAME_MAGIC,
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

pub fn decode_secure_tcp_frame(secure_frame: &[u8], security_cfg: &TcpSecurityCfg) -> io::Result<(SecureTcpFrameMeta, Vec<u8>)> {
    let (header, body) = split_header_body(secure_frame)?;
    let meta = parse_secure_frame_meta(&header, body.len())?;
    if security_cfg.enable_integrity && !meta.integrity_enabled {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received tcp secure frame has integrity disabled",
        ));
    }

    if meta.integrity_enabled {
        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid nonce in tcp secure frame")
        })?;

        let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid tag in tcp secure frame")
        })?;

        let computed_tag = compute_frame_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &computed_tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tcp secure frame integrity verification failed",
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
                "tcp secure frame size mismatch: expected {}, got {}",
                meta.raw_size,
                decoded_payload.len()
            ),
        ));
    }

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest in tcp secure frame",
        )
    })?;

    let computed_digest = sha256(&decoded_payload);
    if !constant_time_eq(&expected_digest, &computed_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tcp secure frame digest verification failed",
        ));
    }

    Ok((meta, decoded_payload))
}

impl TcpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = Socket::bind(addr)?;
        Ok(Self { socket })
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.socket.accept()?;
        Ok((
            TcpStream {
                socket: stream.try_clone()?,
                reader: BufReader::new(stream),
            },
            addr,
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn incoming(&self) -> impl Iterator<Item = io::Result<TcpStream>> + '_ {
        std::iter::repeat_with(move || self.accept().map(|(stream, _)| stream))
    }
}

impl TcpStream {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Self::connect_timeout(addr, Duration::from_secs(30))
    }

    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        let socket = Socket::connect(addr, timeout)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(Duration::from_secs(30)))?;

        let reader_socket = socket.try_clone()?;
        let reader = BufReader::new(reader_socket);

        Ok(Self { socket, reader })
    }

    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.write_all(data)
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.reader.get_mut().read_exact(buf)
    }

    pub fn read_until(&mut self, delimiter: u8, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.reader.read_until(delimiter, buf)
    }

    pub fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
        self.reader.read_line(buf)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.get_mut().read(buf)
    }

    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.reader.get_mut().read_to_end(buf)
    }

    pub fn read_limited(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 8192];
        let mut total_read = 0;
        loop {
            let bytes_read = self.read(&mut chunk)?;
            if bytes_read == 0 {
                break;
            }

            total_read += bytes_read;
            if total_read > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Exceeded maximum allowed bytes",
                ));
            }

            buffer.extend_from_slice(&chunk[..bytes_read]);
        }

        Ok(buffer)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    pub fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.peek(buf)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.socket.set_nodelay(nodelay)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            reader: BufReader::new(self.socket.try_clone()?),
        })
    }

    pub fn send_secure(&mut self, payload: &[u8], security_cfg: &TcpSecurityCfg, compression_cfg: &TcpCompressionCfg) -> io::Result<SecureTcpFrameMeta> {
        let (meta, frame) = encode_secure_tcp_frame(payload, security_cfg, compression_cfg)?;
        if frame.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secure tcp frame too large",
            ));
        }

        let frame_len = frame.len() as u32;
        self.socket.write_all(&frame_len.to_be_bytes())?;
        self.socket.write_all(&frame)?;
        self.socket.flush()?;

        Ok(meta)
    }

    pub fn send_secure_auto(&mut self, payload: &[u8], accept_encoding: &str) -> io::Result<SecureTcpFrameMeta> {
        let algorithm = select_secure_tcp_compression_algorithm(accept_encoding);
        let mut compression_cfg = TcpCompressionCfg::default();
        compression_cfg.algorithm = algorithm;

        self.send_secure(payload, &TcpSecurityCfg::default(), &compression_cfg)
    }

    pub fn recv_secure(&mut self, security_cfg: &TcpSecurityCfg, max_frame_size: usize) -> io::Result<(SecureTcpFrameMeta, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure tcp frame length cannot be zero",
            ));
        }

        if frame_len > max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "secure tcp frame exceeds maximum size: {} > {}",
                    frame_len, max_frame_size
                ),
            ));
        }

        let mut frame = vec![0u8; frame_len];
        self.reader.read_exact(&mut frame)?;

        decode_secure_tcp_frame(&frame, security_cfg)
    }

    pub fn recv_secure_default(&mut self, max_frame_size: usize) -> io::Result<(SecureTcpFrameMeta, Vec<u8>)> {
        self.recv_secure(&TcpSecurityCfg::default(), max_frame_size)
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.get_mut().read(buf)
    }
}

impl Read for &TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.try_clone()?.read(buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl Write for &TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.try_clone()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.try_clone()?.flush()
    }
}

impl Default for TcpSecurityCfg {
    fn default() -> Self {
        Self {
            enable_integrity: true,
            nonce_len: 24,
        }
    }
}

impl Default for TcpCompressionCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Brotli,
            level: CompressionLevel::Default,
            min_size: 512,
        }
    }
}

fn compute_frame_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(TCP_SECURE_FRAME_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    let hmac_key = sha256(&key_material);

    let mut signed = Vec::new();
    signed.extend_from_slice(TCP_SECURE_FRAME_MAGIC.as_bytes());
    signed.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    signed.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &signed)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let split_pos = data.windows(DELIM.len()).position(|w| w == DELIM).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame header separator not found",
        )
    })?;

    let header = String::from_utf8(data[..split_pos].to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame header is not valid UTF-8",
        )
    })?;

    Ok((header, &data[split_pos + DELIM.len()..]))
}

fn parse_secure_frame_meta(header: &str, body_len: usize) -> io::Result<SecureTcpFrameMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != TCP_SECURE_FRAME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure tcp frame magic",
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
                    "unsupported tcp secure frame content-encoding",
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
            "secure tcp frame missing digest",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame missing encoded-size",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame missing issued-at",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure tcp frame body length mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    if integrity_enabled && (nonce_b64.is_empty() || tag_b64.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure tcp frame integrity is enabled but nonce/tag is missing",
        ));
    }

    Ok(SecureTcpFrameMeta {
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
    fn test_select_secure_tcp_compression_algorithm() {
        let selected = select_secure_tcp_compression_algorithm("identity;q=0.1, br;q=1.0");
        assert_eq!(selected, CompressionAlgorithm::Brotli);

        let selected_identity = select_secure_tcp_compression_algorithm("identity");
        assert_eq!(selected_identity, CompressionAlgorithm::Identity);
    }

    #[test]
    fn test_secure_tcp_frame_roundtrip_identity() {
        let payload = b"hello secure tcp".to_vec();
        let security_cfg = TcpSecurityCfg::default();
        let compression_cfg = TcpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (meta, frame) = encode_secure_tcp_frame(&payload, &security_cfg, &compression_cfg)
            .expect("encode must succeed");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_, decoded) =
            decode_secure_tcp_frame(&frame, &security_cfg).expect("decode must succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_tcp_frame_roundtrip_compressed() {
        let payload = vec![b'a'; 4096];
        let security_cfg = TcpSecurityCfg::default();
        let compression_cfg = TcpCompressionCfg {
            enabled: true,
            algorithm: CompressionAlgorithm::Gzip,
            level: CompressionLevel::Default,
            min_size: 1,
        };

        let (meta, frame) = encode_secure_tcp_frame(&payload, &security_cfg, &compression_cfg)
            .expect("encode must succeed");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (_, decoded) =
            decode_secure_tcp_frame(&frame, &security_cfg).expect("decode must succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_tcp_frame_tamper_detected() {
        let payload = b"integrity check payload".to_vec();
        let security_cfg = TcpSecurityCfg::default();
        let compression_cfg = TcpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (_, mut frame) = encode_secure_tcp_frame(&payload, &security_cfg, &compression_cfg)
            .expect("encode must succeed");

        let last = frame.len().saturating_sub(1);
        frame[last] ^= 0x01;

        let result = decode_secure_tcp_frame(&frame, &security_cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_tcp_frame_requires_integrity_when_enabled() {
        let payload = b"no-integrity payload".to_vec();
        let no_integrity_cfg = TcpSecurityCfg {
            enable_integrity: false,
            nonce_len: 0,
        };

        let compression_cfg = TcpCompressionCfg {
            enabled: false,
            algorithm: CompressionAlgorithm::Identity,
            level: CompressionLevel::Default,
            min_size: usize::MAX,
        };

        let (_, frame) = encode_secure_tcp_frame(&payload, &no_integrity_cfg, &compression_cfg)
            .expect("encode must succeed");

        let result = decode_secure_tcp_frame(&frame, &TcpSecurityCfg::default());
        assert!(result.is_err());
    }
}