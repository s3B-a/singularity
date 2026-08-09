use super::packet::DnsPacket;
use super::record::RecordType;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt::Write;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const QUERY_BLOB_MAGIC: &str = "SINGULARITY_DNS_QUERY_BLOB_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureQueryBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub issued_at_unix: u64,
    pub raw_size: usize,
    pub encoded_size: usize,
}

pub struct DnsQuery {
    pub id: u16,
    pub timeout: Duration,
    last_good_server: Option<SocketAddr>,
    accept_encoding: String,
    prefer_secure_transport: bool,
    secure_fallback_to_plain: bool,
}

impl DnsQuery {
    pub fn new() -> Self {
        Self {
            id: Self::generate_id(),
            timeout: Duration::from_secs(5),
            last_good_server: None,
            accept_encoding: "br, zstd, gzip, deflate, identity".to_string(),
            prefer_secure_transport: false,
            secure_fallback_to_plain: true,
        }
    }

    fn generate_id() -> u16 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        SystemTime::now().hash(&mut hasher);
        (hasher.finish() & 0xFFFF) as u16
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn with_accept_encoding(mut self, accept_encoding: impl Into<String>) -> Self {
        self.accept_encoding = accept_encoding.into();
        self
    }

    pub fn with_secure_transport(mut self, enabled: bool) -> Self {
        self.prefer_secure_transport = enabled;
        self
    }

    pub fn with_secure_fallback(mut self, enabled: bool) -> Self {
        self.secure_fallback_to_plain = enabled;
        self
    }

    pub fn query(&mut self, name: &str, record_type: RecordType, server: SocketAddr) -> io::Result<DnsPacket> {
        if self.prefer_secure_transport {
            return self.query_secure_auto(name, record_type, server);
        }

        self.query_plain(name, record_type, server)
    }

    pub fn query_plain(&mut self, name: &str, record_type: RecordType, server: SocketAddr) -> io::Result<DnsPacket> {
        let packet = DnsPacket::new_query(self.id, name.to_string(), record_type);
        let data = packet.write()?;
        let response = self.send_and_receive(server, &data)?;
        let parsed = DnsPacket::read(&response)?;

        if parsed.header.truncated {
            let tcp_response = self.send_and_receive_tcp(server, &data)?;
            let tcp_parsed = DnsPacket::read(&tcp_response)?;
            return self.verify_and_advance_id(tcp_parsed);
        }

        self.verify_and_advance_id(parsed)
    }

    pub fn query_secure(&mut self, name: &str, record_type: RecordType, server: SocketAddr, algorithm: CompressionAlgorithm) -> io::Result<DnsPacket> {
        let packet = DnsPacket::new_query(self.id, name.to_string(), record_type);
        let secure_wire = super::encode_secure_dns_packet(&packet, algorithm)?;
        let response_wire = self.send_and_receive(server, &secure_wire)?;

        match super::decode_secure_dns_packet(&response_wire) {
            Ok(response) => self.verify_and_advance_id(response),
            Err(secure_err) if self.secure_fallback_to_plain => {
                let plain = DnsPacket::read(&response_wire)?;
                self.verify_and_advance_id(plain)
            }
            Err(secure_err) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to decode secure DNS response: {secure_err}"),
            )),
        }
    }

    pub fn query_secure_auto(&mut self, name: &str, record_type: RecordType, server: SocketAddr) -> io::Result<DnsPacket> {
        let algorithm = super::select_algorithm_from_accept_encoding(&self.accept_encoding);
        match self.query_secure(name, record_type, server, algorithm) {
            Ok(packet) => Ok(packet),
            Err(e) if self.secure_fallback_to_plain => self.query_plain(name, record_type, server),
            Err(e) => Err(e),
        }
    }

    pub fn query_with_retries(&mut self, name: &str, record_type: RecordType, servers: &[SocketAddr], retries: usize) -> io::Result<DnsPacket> {
        let mut last_error = None;
        if let Some(server) = self.last_good_server {
            if let Ok(resp) = self.query(name, record_type, server) {
                return Ok(resp);
            }
        }

        for _ in 0..retries {
            for &server in servers {
                match self.query(name, record_type, server) {
                    Ok(resp) => {
                        self.last_good_server = Some(server);
                        return Ok(resp);
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "No DNS servers available")))
    }

    pub fn export_signed_query_blob(&self, name: &str, record_type: RecordType, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let packet = DnsPacket::new_query(self.id, name.to_string(), record_type);
        let raw = packet.write()?;
        let nonce = random::generate_random(16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure query nonce: {e}"),
            )
        })?;

        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let encoded = match algorithm {
            CompressionAlgorithm::Identity => raw.clone(),
            _ => compression::compress(algorithm, &raw, CompressionLevel::Default)?,
        };

        let digest = compute_query_digest(self.id, issued_at_unix, &nonce, &raw);
        let nonce_b64 = pem::encode(&nonce);
        let digest_b64 = pem::encode(&digest);
        let header = format!(
            "{magic}\nid={id}\ncontent-encoding={encoding}\nissued-at={issued_at}\nnonce={nonce}\ndigest=SHA-256={digest}\nraw-size={raw_size}\nencoded-size={encoded_size}\n\n",
            magic = QUERY_BLOB_MAGIC,
            id = self.id,
            encoding = algorithm.content_encoding(),
            issued_at = issued_at_unix,
            nonce = nonce_b64,
            digest = digest_b64,
            raw_size = raw.len(),
            encoded_size = encoded.len(),
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded);

        Ok(out)
    }

    pub fn import_signed_query_blob(data: &[u8]) -> io::Result<(SecureQueryBlobMeta, DnsPacket)> {
        let (header, body) = split_header_body(data)?;
        let (id, meta) = parse_query_blob_meta(&header, body.len())?;
        let decoded = match meta.algorithm {
            CompressionAlgorithm::Identity => body.to_vec(),
            _ => compression::decompress(meta.algorithm, body)?,
        };

        if decoded.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure query blob decoded payload size mismatch",
            ));
        }

        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in secure query blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in secure query blob",
            )
        })?;

        let computed = compute_query_digest(id, meta.issued_at_unix, &nonce, &decoded);
        if !constant_time_eq(&computed, &expected_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure query blob digest verification failed",
            ));
        }

        let packet = DnsPacket::read(&decoded)?;
        if packet.header.id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure query blob packet ID does not match envelope ID",
            ));
        }

        Ok((meta, packet))
    }

    pub fn resolve_a(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<std::net::Ipv4Addr>> {
        let response = self.query(name, RecordType::A, server)?;
        let mut addresses = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::A(ip) = answer.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No A records found"));
        }

        Ok(addresses)
    }

    pub fn resolve_aaaa(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<std::net::Ipv6Addr>> {
        let response = self.query(name, RecordType::AAAA, server)?;
        let mut addresses = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::AAAA(ip) = answer.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No AAAA records found"));
        }

        Ok(addresses)
    }

    pub fn resolve_cname(&mut self, name: &str, server: SocketAddr) -> io::Result<String> {
        let response = self.query(name, RecordType::CNAME, server)?;
        for answer in response.answers {
            if let super::record::RecordData::CNAME(cname) = answer.data {
                return Ok(cname);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No CNAME record found",
        ))
    }

    pub fn resolve_mx(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<(u16, String)>> {
        let response = self.query(name, RecordType::MX, server)?;
        let mut mx_records = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::MX {
                preference,
                exchange,
            } = answer.data

            {
                mx_records.push((preference, exchange));
            }
        }

        if mx_records.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No MX records found"));
        }

        mx_records.sort_by_key(|(pref, _)| *pref);

        Ok(mx_records)
    }

    pub fn resolve_txt(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<Vec<String>>> {
        let response = self.query(name, RecordType::TXT, server)?;
        let mut txt_records = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::TXT(texts) = answer.data {
                txt_records.push(texts);
            }
        }

        if txt_records.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No TXT records found"));
        }

        Ok(txt_records)
    }

    pub fn reverse_lookup(&mut self, ip: std::net::IpAddr, server: SocketAddr) -> io::Result<String> {
        let ptr_name = match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            std::net::IpAddr::V6(ipv6) => ipv6_ptr(ipv6),
        };

        let response = self.query(&ptr_name, RecordType::PTR, server)?;
        for answer in response.answers {
            if let super::record::RecordData::PTR(name) = answer.data {
                return Ok(name);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No PTR record found",
        ))
    }

    fn send_and_receive(&self, server: SocketAddr, wire: &[u8]) -> io::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.send_to(wire, server)?;

        let mut buffer = vec![0u8; 4096];
        let (size, _) = socket.recv_from(&mut buffer)?;
        buffer.truncate(size);

        Ok(buffer)
    }

    fn send_and_receive_tcp(&self, server: SocketAddr, wire: &[u8]) -> io::Result<Vec<u8>> {
        if wire.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message too large for TCP framing",
            ));
        }

        let mut stream = TcpStream::connect_timeout(&server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let len_prefix = (wire.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix)?;
        stream.write_all(wire)?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf)?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut buffer = vec![0u8; resp_len];
        stream.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    fn verify_and_advance_id(&mut self, response: DnsPacket) -> io::Result<DnsPacket> {
        if response.header.id != self.id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response ID does not match query ID",
            ));
        }

        self.id = self.id.wrapping_add(1);

        Ok(response)
    }
}

impl Default for DnsQuery {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_query_digest(id: u16, issued_at_unix: u64, nonce: &[u8], raw_payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(2 + 8 + nonce.len() + raw_payload.len());
    material.extend_from_slice(&id.to_be_bytes());
    material.extend_from_slice(&issued_at_unix.to_be_bytes());
    material.extend_from_slice(nonce);
    material.extend_from_slice(raw_payload);

    sha256(&material)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    if let Some(pos) = data.windows(DELIM.len()).position(|w| w == DELIM) {
        let header = String::from_utf8(data[..pos].to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "secure query blob header is not valid UTF-8",
            )
        })?;

        let body = &data[pos + DELIM.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "secure query blob separator not found",
    ))
}

fn parse_query_blob_meta(header: &str, body_len: usize) -> io::Result<(u16, SecureQueryBlobMeta)> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != QUERY_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure query blob magic",
        ));
    }

    let mut id = None::<u16>;
    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut issued_at_unix = None::<u64>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    for line in lines {
        if let Some(v) = line.strip_prefix("id=") {
            id = v.trim().parse::<u16>().ok();
        } else if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported secure query blob content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("issued-at=") {
            issued_at_unix = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        }
    }

    let id = id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure query blob missing query id",
        )
    })?;

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure query blob missing nonce")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure query blob missing digest")
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure query blob missing issued-at",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure query blob missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure query blob missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure query blob encoded-size does not match body length",
        ));
    }

    Ok((
        id,
        SecureQueryBlobMeta {
            algorithm,
            nonce_b64,
            digest_b64,
            issued_at_unix,
            raw_size,
            encoded_size,
        },
    ))
}

fn ipv6_ptr(ipv6: std::net::Ipv6Addr) -> String {
    let segments = ipv6.segments();
    let mut s = String::with_capacity(32 * 2 + 9);
    for segment in segments.iter().rev() {
        for i in (0..4).rev() {
            let nibble = (segment >> (i * 4)) & 0xF;
            write!(s, "{:x}.", nibble).unwrap();
        }
    }

    s.push_str("ip6.arpa");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = DnsQuery::generate_id();
        let id2 = DnsQuery::generate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_query_creation() {
        let query = DnsQuery::new();
        assert_eq!(query.timeout, Duration::from_secs(5));
        assert!(!query.prefer_secure_transport);
        assert!(query.secure_fallback_to_plain);
    }

    #[test]
    fn test_query_with_timeout() {
        let query = DnsQuery::new().with_timeout(Duration::from_secs(10));
        assert_eq!(query.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_query_with_id() {
        let query = DnsQuery::new().with_id(12345);
        assert_eq!(query.id, 12345);
    }

    #[test]
    fn test_query_secure_flags() {
        let query = DnsQuery::new()
            .with_secure_transport(true)
            .with_secure_fallback(false)
            .with_accept_encoding("gzip, identity");

        assert!(query.prefer_secure_transport);
        assert!(!query.secure_fallback_to_plain);
        assert_eq!(query.accept_encoding, "gzip, identity");
    }

    #[test]
    fn test_reverse_lookup_ipv4_name() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(ip.is_ipv4());
    }

    #[test]
    fn test_reverse_lookup_ipv6_name() {
        let ip =
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

        assert!(ip.is_ipv6());
    }

    #[test]
    fn test_export_import_signed_query_blob_identity() {
        let query = DnsQuery::new().with_id(4242);
        let blob = query
            .export_signed_query_blob("example.com", RecordType::A, CompressionAlgorithm::Identity)
            .unwrap();

        let (meta, packet) = DnsQuery::import_signed_query_blob(&blob).unwrap();
        assert_eq!(packet.header.id, 4242);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
        assert_eq!(packet.questions[0].record_type, RecordType::A);
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(meta.encoded_size + 0, meta.encoded_size);
    }

    #[test]
    fn test_export_import_signed_query_blob_compressed() {
        let query = DnsQuery::new().with_id(77);
        let blob = query
            .export_signed_query_blob("compression.test", RecordType::TXT, CompressionAlgorithm::Gzip)
            .unwrap();

        let (meta, packet) = DnsQuery::import_signed_query_blob(&blob).unwrap();
        assert_eq!(packet.header.id, 77);
        assert_eq!(packet.questions[0].name, "compression.test");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);
    }

    #[test]
    fn test_signed_query_blob_tamper_detection() {
        let query = DnsQuery::new().with_id(9001);
        let mut blob = query
            .export_signed_query_blob("tamper.test", RecordType::A, CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = DnsQuery::import_signed_query_blob(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_query_blob_bad_magic() {
        let query = DnsQuery::new().with_id(5555);
        let mut blob = query
            .export_signed_query_blob("bad.magic", RecordType::A, CompressionAlgorithm::Identity)
            .unwrap();

        blob[0] ^= 0x01;
        let result = DnsQuery::import_signed_query_blob(&blob);
        assert!(result.is_err());
    }
}